# crypto_playpen

Using Tari Project's crypto::ristretto to create and verify signatures on a RAID_ID

``` Text
Owner has RAID_ID

 - RAID_ID (from DNS TXT record): "RYqMMuSmBZFQkgp"

Owner sign RAID_ID

 - Secret Key (re-used):       "29bb078b7b2b01e62dd684cd20742b510ece6175fa58d7a79cceeefe5297a804"
 - Public Key (P):             "ca469346d7643336c19155fdf5c6500a5232525ce4eba7e4db757639159e9861"
 - Secret Nonce (new):         "ee5c79ffd1f68a0a759be9485fc5be86da3eba6cb5b5f38c55f66154c54cc200"
 - Public Nonce (R):           "b8ce94a968bf7c1631872a0e64ae963fa6306f83223af950dd434f030071fc64"
 - Challenge: e=H(R|P|RAID_ID) "5a9754df52d3e196c86220142abfb4b0c7d7300d56b5d60320901bfa7f88b8d6"
 - RAID_ID Signature (s):      "61c23fd584d3d48fcbcd63f9c96dc61f33d9343be3c5022e461a7e0be0aa0f06"

Verifier check signature, using (s,R,P,RAID_ID) from DNS TXT record

 - RAID_ID Pub Sig (S=s·G):    "a63dd154cf55affc8a298071cf7b173845250d87d6a2a3ee3b21c65cd9801e65"
 - Challenge: e=H(R|P|RAID_ID) "5a9754df52d3e196c86220142abfb4b0c7d7300d56b5d60320901bfa7f88b8d6"
 - Asserted recalculation of hashed challenge
 - Assert: s·G = R + e·P
 - RAID_ID Signature is valid!

Anomaly with RistrettoSecretKey (used above) to hex

 - Assert: [Challenge::<Blake256>.hash().to_hex()] vs. [RistrettoSecretKey.to_hex()]
thread 'main' panicked at 'assertion failed: `(left == right)`
  left: `"5a9754df52d3e196c86220142abfb4b0c7d7300d56b5d60320901bfa7f88b8d6"`,
 right: `"51d4d826fccaf21de66b8dcddb0e62a1c6d7300d56b5d60320901bfa7f88b806"`', src\main.rs:95:5
note: Run with `RUST_BACKTRACE=1` environment variable to display a backtrace.
```
