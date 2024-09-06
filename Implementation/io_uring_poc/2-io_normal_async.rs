use std::convert::TryInto;
use std::process::Command;
use std::io::Write;
use std::sync::Arc;
use tun_tap::{Iface, Mode};

// Programme de test pour la partie `Performances` utilisant des IO classiques et un mécanisme asynchrone

const ICMP_ECHO_REPLY: u8 = 0;

fn calculate_checksum(data: &mut [u8]) {
    let mut f = 0;
    let mut chk: u32 = 0;
    while f + 2 <= data.len() {
        chk += u16::from_le_bytes(data[f..f+2].try_into().unwrap()) as u32;
        f += 2;
    }

    while chk > 0xffff {
        chk = (chk & 0xffff) + (chk >> 2*8);
    }

    let mut chk = chk as u16;

    chk = !chk & 0xffff;

    data[3] = (chk >> 8) as u8;
    data[2] = (chk & 0xff) as u8;
}

pub struct Connection<'a> {
    ip: etherparse::Ipv4Header,
    icmp_id: u16,
    seq_no: u16,
    data: &'a [u8],
}

impl<'a> Connection<'a> {
    pub fn start(iph: etherparse::Ipv4HeaderSlice, data: &'a [u8]) -> std::io::Result<Option<Self>> {
        let c = Connection {
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Icmp,
                iph.destination().try_into().unwrap(),
                iph.source().try_into().unwrap(),
            ),
            icmp_id: u16::from_be_bytes(data[4..6].try_into().unwrap()),
            seq_no: u16::from_be_bytes(data[6..8].try_into().unwrap()),
            data,
        };

        Ok(Some(c))
    }

    pub async fn respond(&mut self, tun: &Arc<tun_tap::Iface>) -> std::io::Result<usize> {
        let mut buf = [0u8; 1500];

        let _ = self.ip.set_payload_len(84-20 as usize);

        let mut unwritten = &mut buf[..];
        let _ = self.ip.write(&mut unwritten);

        let mut icmp_reply = [0u8; 64];
        icmp_reply[0] = ICMP_ECHO_REPLY;                                // type
        icmp_reply[1] = 0;                                              // code - always 0?

        icmp_reply[2] = 0x00;                                           // checksum = 2 & 3, empty for now
        icmp_reply[3] = 0x00;                                           //

        icmp_reply[4] = ((self.icmp_id >> 8) & 0xff) as u8;             // id = 4 & 5
        icmp_reply[5] = (self.icmp_id & 0xff) as u8;

        icmp_reply[6] = ((self.seq_no >> 8) & 0xff) as u8;              // seq_no = 6 & 7
        icmp_reply[7] = (self.seq_no & 0xff) as u8;

        icmp_reply[8..64].clone_from_slice(&self.data[8..64]);

        calculate_checksum(&mut icmp_reply);

        let _ = unwritten.write(&icmp_reply)?;

        let unwritten_len = unwritten.len();
        let nbytes = tun.send(&buf[..buf.len() - unwritten_len])?;

        Ok(nbytes)
    }
}

fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new(cmd)
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execute {}", cmd);
}

#[tokio::main]
async fn main() {

    let nic = Arc::new(Iface::without_packet_info("tun0", Mode::Tun).unwrap());
    cmd("ip", &["addr", "add", "dev", nic.name(), "192.168.0.1/24"]);
    cmd("ip", &["link", "set", "up", "dev", nic.name()]);

    let mut handles = vec![];

    for _ in 0..30 {

        let nic_clone = Arc::clone(&nic);
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {

                let nbytes = nic_clone.recv(&mut buf[..]).unwrap();
                let packet = buf[..nbytes].to_vec();

                match etherparse::Ipv4HeaderSlice::from_slice(&packet) {
                    Ok(iph) => {
                        let proto = iph.protocol();

                        if proto != 1 {
                            return;
                        }

                        let data_buf = &packet[iph.slice().len()..];
                        if let Some(mut c) = Connection::start(iph, data_buf).unwrap() {
                            c.respond(&nic_clone).await.unwrap();
                        }
                    }
                    Err(e) => {
                        eprintln!("Ignoring weird packet {:?}", e);
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
