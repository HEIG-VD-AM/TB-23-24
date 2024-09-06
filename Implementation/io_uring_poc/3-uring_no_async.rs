use std::convert::TryInto;
use std::process::Command;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use glommio::io::BufferedFile;
use glommio::LocalExecutor;
use tun_tap::{Iface, Mode};

// Programme de test pour la partie `Performances` utilisant io_uring et n'utilisant pas de mécanisme asynchrone

const ICMP_ECHO_REPLY   : u8 = 0;
const ICMP_PACKET_SIZE : usize = 84;

fn calculate_checksum(data: &mut [u8]) {
    let mut f = 0;
    let mut chk: u32 = 0;
    while f + 2 <= data.len() {
        chk += u16::from_le_bytes(data[f..f+2].try_into().unwrap()) as u32;
        f += 2;
    }

    //chk &= 0xffffffff; // unneccesary
    while chk > 0xffff {
        chk = (chk & 0xffff) + (chk >> 2*8);
    }

    let mut chk = chk as u16;

    chk = !chk & 0xffff;

    // endianness
    //chk = chk >> 8 | ((chk & 0xff) << 8);

    data[3] = (chk >> 8) as u8;
    data[2] = (chk & 0xff) as u8;
}

pub struct Connection <'a> {
    ip: etherparse::Ipv4Header,
    icmp_id: u16,
    seq_no: u16,
    data: &'a [u8],
}

impl<'a> Connection <'a> {
    pub fn start(iph: etherparse::Ipv4HeaderSlice, data: &'a [u8]) -> std::io::Result<Option<Self>> {
        let c = Connection {
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Icmp,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            ),
            icmp_id: u16::from_be_bytes(data[4..6].try_into().unwrap()),
            seq_no: u16::from_be_bytes(data[6..8].try_into().unwrap()),
            data,
        };

        Ok(Some(c))
    }

    pub async fn respond(&mut self, file: &BufferedFile) -> std::io::Result<usize> {
        let mut buf = [0u8; 1500];

        let _ = self.ip.set_payload_len(ICMP_PACKET_SIZE-20 as usize);

        let mut unwritten = &mut buf[..];
        let _ = self.ip.write(&mut unwritten);

        let mut icmp_reply = [0u8; 64];
        icmp_reply[0] = ICMP_ECHO_REPLY;                                // type
        icmp_reply[1] = 0;			                        // code - always 0?

        icmp_reply[2] = 0x00;                                           // checksum = 2 & 3, empty for now
        icmp_reply[3] = 0x00;                                           //

        icmp_reply[4] = ((self.icmp_id >> 8) & 0xff) as u8;             // id = 4 & 5
        icmp_reply[5] = (self.icmp_id & 0xff) as u8;

        icmp_reply[6] = ((self.seq_no >> 8) & 0xff) as u8;              // seq_no = 6 & 7
        icmp_reply[7] = (self.seq_no & 0xff) as u8;

        icmp_reply[8..64].clone_from_slice(&self.data[8..64]);

        calculate_checksum(&mut icmp_reply);

        let _ = unwritten.write(&icmp_reply);

        let unwritten = unwritten.len();
        let nbytes = file.write_at(buf[..buf.len() - unwritten].to_vec(), 0).await.unwrap();

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
    let ex = LocalExecutor::default();
    ex.run(async {
        let nic = Iface::without_packet_info("tun0", Mode::Tun).unwrap();
        cmd("ip", &["addr", "add", "dev", nic.name(), "192.168.0.1/24"]);
        cmd("ip", &["link", "set", "up", "dev", nic.name()]);

        let fd = nic.as_raw_fd();
        let file = unsafe { BufferedFile::from_raw_fd(fd) };

        loop {
            let buf  = file.read_at(0, 88).await.unwrap();
            let nbytes = buf.len();

            match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
                Ok(iph) => {

                    let proto = iph.protocol();

                    if proto != 1 {
                        continue;
                    }

                    let data_buf = &buf[iph.slice().len()..nbytes];

                    if let Some(mut c) = Connection::start(
                        iph,
                        data_buf,
                    ).unwrap() {
                        let _ = c.respond(&file).await.unwrap();
                    }
                }
                Err(e) => {
                    eprintln!("Ignoring weird packet {:?}", e);
                }
            }
        }
    });

}
