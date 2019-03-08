extern crate crypto;

use crypto::ristretto::{RistrettoSecretKey, RistrettoPublicKey};
use crypto::keys::SecretKeyFactory;
use crypto::keys::PublicKey;
use crypto::common::ByteArray;

fn main() {
    let mut rng = rand::OsRng::new().unwrap();
    let sk = RistrettoSecretKey::random(&mut rng);
    let pk = RistrettoPublicKey::from_secret_key(&sk);

    println!("Secret Key: {:?}", sk.to_hex());
    println!("Public Key: {:?}", pk.to_hex());
}
