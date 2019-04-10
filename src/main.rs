extern crate crypto;

use crypto::{
    ristretto::{RistrettoSecretKey, RistrettoPublicKey, RistrettoSchnorr},
    keys::{SecretKeyFactory, PublicKey},
    challenge::Challenge,
    common::{Blake256, ByteArray},
};
use digest::Digest;
use curve25519_dalek::scalar::Scalar;

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

    println!(" - Secret Key (re-used):                     {:?}", k.to_hex());
    println!(" - Public Key (P):                           {:?}", P.to_hex());

    // - Generate nonce pair
    let (r, R) = get_keypair();
    println!(" - Secret Nonce (new):                       {:?}", r.to_hex());
    println!(" - Public Nonce (R):                         {:?}", R.to_hex());

    // - Generate challenge
    let e_new = Challenge::<Blake256>::new();
    let e_signer = e_new.concat(R.to_bytes()).
        concat(P.to_bytes()).
        concat(&raid_id.clone().into_bytes());
    let e_signer_hash = e_signer.clone().hash();
    println!(" - Challenge: e_signer_hash=H(R|P|RAID_ID)   {:?}", e_signer_hash.to_hex());

    // - Sign the RAID_ID
    let sig = RistrettoSchnorr::sign(k, r, e_signer.clone()).unwrap();
    let sig_known = sig.get_signature();
    println!(" - RAID_ID Signature (s):                    {:?}", sig_known.to_hex());
    
    // - Assert signature
    let R_calc = sig.get_public_nonce();
    assert_eq!(R, *R_calc);
    assert!(sig.verify(&P, e_signer.clone()));
    
    // Assert signature as verifier
    println!("");
    println!("Verifier check signature, using (s,R,P,RAID_ID) from DNS TXT record");
    println!("");
    let S = RistrettoPublicKey::from_secret_key(&sig_known);
    println!(" - RAID_ID Pub Sig (S=s·G):                  {:?}", S.to_hex());
    let e_verifier_hash = hash_challange(R.to_bytes(), P.to_bytes(), &raid_id.clone().into_bytes());
    println!(" - Challenge: e_verifier_hash=H(R|P|RAID_ID) {:?}", e_verifier_hash.to_hex());    
    let e_verifier_mod_n = RistrettoSecretKey::from_hex(&e_verifier_hash.to_hex()).unwrap();
    println!(" - Challenge: e_verifier_mod_n:              {:?}", e_verifier_mod_n.to_hex());
    println!(" - Assert: s·G = R + e_verifier_mod_n·P");
    assert_eq!(S, R + e_verifier_mod_n.clone() * P);
    println!(" - RAID_ID Signature is valid!");
    
    // - Additional asserts, for testing
    println!("");
    println!("Additional asserts, for testing");
    println!("");
    println!(" - Assert: e_signer_hash = e_verifier_hash");
    assert_eq!(e_signer_hash.to_hex(), e_verifier_hash.to_hex());
    println!(" - Recalculation of hashed challenge is valid!");
    println!(" - Assert: R + e_signer_mod_n·P = R + e_verifier_mod_n·P");
    let e_signer_mod_n = RistrettoSecretKey::from_hex(&e_signer_hash.to_hex()).unwrap();
    assert_eq!(R + e_signer_mod_n.clone() * P, R + e_verifier_mod_n.clone() * P);
    println!(" - Equation is valid!");
    

}
