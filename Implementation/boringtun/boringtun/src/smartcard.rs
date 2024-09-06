use std::convert::TryInto;
use card_backend_pcsc::PcscBackend;
use openpgp_card::{Card, KeyType};
use openpgp_card::crypto_data::Cryptogram;
use x25519_dalek::{SharedSecret, StaticSecret, PublicKey};
use rpassword::read_password;
use std::sync::{Arc, Mutex};
use hex::decode_to_slice;

const SMARTCARD_INDICATOR: [u8; 32] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

lazy_static::lazy_static! {
    static ref USER_PIN: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
}

pub fn set_user_pin() {
    let backends_result = PcscBackend::cards(None)
        .expect("Failed to get backends");

    // Vérifie si une carte existe et demande le code PIN de l'utilisateur
    if backends_result.filter_map(|c| c.ok()).next().is_some() {
        println!("Please enter your smartcard user PIN: ");
        let pin = read_password().expect("Failed to read PIN");
        let mut user_pin = USER_PIN.lock().unwrap();
        *user_pin = pin;
    }
}

fn get_user_pin() -> String {
    // Récupère le code PIN de l'utilisateur et le retourne
    let user_pin = USER_PIN.lock().unwrap();
    user_pin.clone()
}

pub fn extended_diffie_hellman(static_secret: &StaticSecret, peer_public_key: &PublicKey) -> SharedSecret {

    // Vérifie si la clé privée annoncée dans la configuration correspond à la valeur indiquant qu'une smartcard est utilisée
    // Si ce n'est pas le cas, alors on utilise le secret statique pour effectuer le calcul de la clé partagée
    if *static_secret.as_bytes() != SMARTCARD_INDICATOR {
        return static_secret.diffie_hellman(&peer_public_key);
    } else {
        let backends_result = PcscBackend::cards(None)
            .expect("Failed to get backends");

        // Cherche la carte connectée afin d'effectuer le calcul de la clé partagée
        for b in backends_result.filter_map(|c| c.ok()) {
            let mut card = Card::new(b)
                .expect("Card creation failed");

            let mut transaction = card.transaction()
                .expect("Transaction creation failed");

            // Utilise le code PIN de l'utilisateur pour déverrouiller la carte
            let _ = transaction.verify_pw1_user(get_user_pin().as_ref());

            // Effectue le calcul de la clé partagée
            let shared_secret_bytes = transaction.decipher(Cryptogram::ECDH(&*peer_public_key.as_bytes()))
                .expect("Diffie-Hellman failed");

            // Convertit le résultat en tableau d'octets
            let shared_secret_bytes_array: [u8; 32] = shared_secret_bytes.try_into()
                .expect("Failed to convert result to bytes");

            // Crée un objet SharedSecret à partir du tableau d'octets et le retourne
            return SharedSecret::from_bytes(shared_secret_bytes_array);
        }

        panic!("No valid card found");
    }
}

pub fn extended_public_key_derivation(static_secret: &StaticSecret) -> PublicKey {
    if *static_secret.as_bytes() != SMARTCARD_INDICATOR {
        return PublicKey::from(static_secret);
    } else {
        let backends_result = PcscBackend::cards(None)
            .expect("Failed to get backends");

        for b in backends_result.filter_map(|c| c.ok()) {
            let mut card = Card::new(b)
                .expect("Card creation failed");

            let mut transaction = card.transaction()
                .expect("Failed to create transaction");

            if let Ok(public_key) = transaction.public_key(KeyType::Decryption) {
                let public_key_str = public_key.to_string();
                let public_key_slice = &public_key_str[public_key_str.len() - 64..];
                let mut public_key_decoded = [0; 32];
                decode_to_slice(public_key_slice, &mut public_key_decoded).expect("Failed to decode public key");
                return PublicKey::from(public_key_decoded);
            } else {
                panic!("Failed to get public key");
            }
        }

        panic!("No valid card found");
    }
}

