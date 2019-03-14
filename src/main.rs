extern crate crypto;

use crypto::{
    ristretto::{RistrettoSecretKey, RistrettoPublicKey, RistrettoSchnorr},
    keys::{SecretKeyFactory, PublicKey},
    challenge::Challenge,
    common::{Blake256, ByteArray},
};
use digest::Digest;

fn main() {

    fn get_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
        let mut rng = rand::OsRng::new().unwrap();
        let k = RistrettoSecretKey::random(&mut rng);
        let pk = RistrettoPublicKey::from_secret_key(&k);
        (k, pk)
    }

    fn hash_challange(R_byts: &[u8], P_bytes: &[u8], msg_bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Blake256::new();
        hasher.input(R_byts);
        hasher.input(P_bytes);
        hasher.input(msg_bytes);
        let e = hasher.result().to_vec();
        (e)
    }

    // RAID_ID
    println!("");
    println!("Owner has RAID_ID");
    println!("");

    let raid_id = String::from("RYqMMuSmBZFQkgp");
    println!(" - RAID_ID (from DNS TXT record: {:?}", raid_id);

    // Sign
    println!("");
    println!("Owner sign RAID_ID");
    println!("");

    // - Secret key is known, generate public key, assert
    let k = RistrettoSecretKey::from_hex("29bb078b7b2b01e62dd684cd20742b510ece6175fa58d7a79cceeefe5297a804").unwrap();
    let P = RistrettoPublicKey::from_secret_key(&k);
    let P_known = RistrettoPublicKey::from_hex("ca469346d7643336c19155fdf5c6500a5232525ce4eba7e4db757639159e9861").unwrap();
    assert_eq!(P, P_known);

    println!(" - Secret Key (re-used):       {:?}", k.to_hex());
    println!(" - Public Key (P):             {:?}", P.to_hex());

    // - Generate nonce pair
    let (r, R) = get_keypair();
    println!(" - Secret Nonce (new):         {:?}", r.to_hex());
    println!(" - Public Nonce (R):           {:?}", R.to_hex());

    // - Generate challenge
    let e_new = Challenge::<Blake256>::new();
    let e = e_new.concat(R.to_bytes()).
        concat(P.to_bytes()).
        concat(&raid_id.clone().into_bytes());
    let e_hash = e.clone().hash();
    println!(" - Challenge: e=H(R|P|RAID_ID) {:?}", e_hash.to_hex());

    // - Sign the RAID_ID
    let sig = RistrettoSchnorr::sign(k, r, e.clone()).unwrap();
    let sig_known = sig.get_signature();
    println!(" - RAID_ID Signature (s):      {:?}", sig_known.to_hex());
    
    // - Assert signature
    let R_calc = sig.get_public_nonce();
    assert_eq!(R, *R_calc);
    assert!(sig.verify(&P, e.clone()));
    
    // Assert signature as verifier
    println!("");
    println!("Verifier check signature, using (s,R,P,RAID_ID) from DNS TXT record");
    println!("");
    let S = RistrettoPublicKey::from_secret_key(&sig_known);
    println!(" - RAID_ID Pub Sig (S=s·G):    {:?}", S.to_hex());
    let e_verifier = hash_challange(R.to_bytes(), P.to_bytes(), &raid_id.clone().into_bytes());
    println!(" - Challenge: e=H(R|P|RAID_ID) {:?}", e_verifier.to_hex());    
    assert_eq!(e_hash.to_hex(), e_verifier.to_hex());
    println!(" - Asserted recalculation of hashed challenge");
    let e_key = RistrettoSecretKey::from_hex(&e_verifier.to_hex()).unwrap();
    println!(" - Assert: s·G = R + e·P");
    assert_eq!(S, R + e_key.clone() * P);
    println!(" - RAID_ID Signature is valid!");
    
    //Assert challenge
    println!("");
    println!("Anomaly with RistrettoSecretKey (used above) to hex");
    println!("");

    println!(" - Assert: [Challenge::<Blake256>.hash().to_hex()] vs. [RistrettoSecretKey.to_hex()]");
    assert_eq!(e_hash.to_hex(), e_key.to_hex());
    println!(" - Challenge (in hex) is valid!");
    println!("");

}
