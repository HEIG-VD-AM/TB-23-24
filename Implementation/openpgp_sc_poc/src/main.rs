use card_backend_pcsc::PcscBackend;
use openpgp_card::{Card, KeyType};
use openpgp_card::crypto_data::Cryptogram;
use rand_core::{OsRng};
use x25519_dalek::{PublicKey, StaticSecret};
use anyhow::{Result, anyhow};
use hex::{decode_to_slice};

fn generate_key() -> (StaticSecret, PublicKey) {
    let private_key = StaticSecret::random_from_rng(&mut OsRng);
    let public_key = PublicKey::from(&private_key);
    (private_key, public_key)
}

fn dalek_case(my_private_key: StaticSecret, peer_public: PublicKey) -> Result<[u8; 32]> {

    Ok(*my_private_key.diffie_hellman(&peer_public).as_bytes())
}

fn openpgp_case(peer_public_bytes: Vec<u8>) -> Result<[u8; 32]> {

    // Utilisation de la librairie pour communiquer avec la carte
    let backends = PcscBackend::cards(None)?;

    // On itère sur les cartes disponibles
    for b in backends.filter_map(|c| c.ok()) {

        println!("Found card !");

        // Création d'une transaction (structure qui permet d'effectuer des opérations sur la carte)
        let mut card = Card::new(b)?;
        let mut transaction = card.transaction()?;

        // Permet de déverouiller l'accès à la carte
        transaction.verify_pw1_user("123456".as_ref())?;

        // On envoie à la carte la clé publique de notre pair afin qu'elle réalise le calcul de la clé partagée
        match transaction.decipher(Cryptogram::ECDH(&*peer_public_bytes)) {
            Ok(res) => {
                let res_bytes: [u8; 32] = res.try_into()
                    .map_err(|_| anyhow!("Failed to convert: Vec length is not 32"))?;
                return Ok(res_bytes);
            },
            Err(e) => {
                println!("ECDH failed: {}", e);
                return Ok([0; 32]);
            }
        }
    }

    Ok([0; 32])
}
fn get_public_from_smartcard() -> Result<PublicKey> {
    // Utilisation de la librairie pour communiquer avec la carte
    let backends = PcscBackend::cards(None)?;

    // On itère sur les cartes disponibles
    for b in backends.filter_map(|c| c.ok()) {
        // Création d'une transaction (structure qui permet d'effectuer des opérations sur la carte)
        let mut card = Card::new(b)?;
        let mut transaction = card.transaction()?;

        // Récupération de la clé publique
        if let Ok(public_key) = transaction.public_key(KeyType::Decryption) {
            let public_key_str = public_key.to_string();
            let public_key_slice = &public_key_str[public_key_str.len() - 64..];
            let mut public_key_decoded = [0; 32];
            decode_to_slice(public_key_slice, &mut public_key_decoded).expect("Failed to decode public key");
            return Ok(PublicKey::from(public_key_decoded));
        } else {
            println!("Failed to retrieve public key.");
        }
    }
    Ok(PublicKey::from([0; 32]))
}

fn main() -> Result<()> {

    // Création d'une paire de clés qui représente celle d'un pair dans la configuration WireGuard
    println!("Creating keys");
    let (peer_b_private, peer_b_public) = generate_key();
    let peer_b_public_bytes = peer_b_public.as_bytes().to_vec();

    // Récupération de la clé publique liée à la clé privée présente sur la smartcard
    let my_public_key = get_public_from_smartcard()?;

    // Création du secret partagé avec ECDH
    let shared_key_a = dalek_case(peer_b_private, my_public_key)?;
    let shared_key_b = openpgp_case(peer_b_public_bytes)?;

    println!("Shared key A (dalek)     : {:?}", shared_key_a);
    println!("Shared key B (openpgp)   : {:?}", shared_key_b);

    // Vérification que les deux clés partagées sont identiques
    assert_eq!(shared_key_a, shared_key_b);

    Ok(())
}
