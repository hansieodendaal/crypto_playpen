extern crate crypto;

use crypto::ristretto::{RistrettoSecretKey, RistrettoPublicKey, RistrettoSchnorr};
use crypto::keys::{SecretKeyFactory, PublicKey};
use crypto::challenge::Challenge;
use crypto::common::{Blake256, ByteArray};

fn main() {

    fn get_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
        let mut rng = rand::OsRng::new().unwrap();
        let k = RistrettoSecretKey::random(&mut rng);
        let pk = RistrettoPublicKey::from_secret_key(&k);
        (k, pk)
    }

    // RAID_ID
    println!("");
    println!("Owner has RAID_ID");
    println!("");

    let raid_id = String::from("RSt3HqhdvyuBkxqvZfhDtQT1WBC6e11bJ1");
    println!("RAID_ID:                  {:?}", raid_id);

    // Sign
    println!("");
    println!("Owner sign RAID_ID");
    println!("");

    // - Secret key is known, generate public key, assert
    let k = RistrettoSecretKey::from_hex("29bb078b7b2b01e62dd684cd20742b510ece6175fa58d7a79cceeefe5297a804").unwrap();
    let P = RistrettoPublicKey::from_secret_key(&k);
    let P_known = RistrettoPublicKey::from_hex("ca469346d7643336c19155fdf5c6500a5232525ce4eba7e4db757639159e9861").unwrap();
    assert_eq!(P, P_known);

    println!("Secret Key:               {:?}", k.to_hex());
    println!("Public Key (known):       {:?}", P.to_hex());

    // - Generate nonce pair
    let (r, R) = get_keypair();
    println!("Secret Nonce:             {:?}", r.to_hex());
    println!("Public Nonce (shared):    {:?}", R.to_hex());

    // - Generate challenge
    let e_new = Challenge::<Blake256>::new();
    let e = e_new.concat(R.to_bytes()).
        concat(P.to_bytes()).
        concat(&raid_id.into_bytes());
    let e_hash = e.clone().hash();
    println!("Challenge:                {:?}", e_hash.to_hex());

    // - Sign the RAID_ID
    let s = RistrettoSchnorr::sign(k, r, e.clone()).unwrap();
    println!("RAID_ID Signature:        {:?}", s.get_signature().to_hex());
    
    // - Assert signature
    let R_calc = s.get_public_nonce();
    assert_eq!(R, *R_calc);
    assert!(s.verify(&P, e.clone()));
    
    // Assert signature as verifier
    println!("");
    println!("Verifier check signature");
    println!("");
    println!(" - Calculate s·G");
    let S = RistrettoPublicKey::from_secret_key(&s.get_signature());
    println!("RAID_ID Public Signature: {:?}", S.to_hex());
    println!(" - Calculate challenge");
    let e_key = RistrettoSecretKey::from_hex(&e_hash.to_hex()).unwrap();
    println!("Challenge :               {:?}", e_key.to_hex());
    println!("Assert: s·G = R + e·P");
    assert_eq!(S, R + e_key * P);
    println!("RAID_ID Signature is valid");
    println!("");

}
