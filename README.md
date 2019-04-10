# crypto_playpen

Using Tari Project's crypto::ristretto to create and verify signatures on a RAID_ID.

Note: `e_verifier_hash` may be equal to `e_verifier_mod_n` as shown below, but this is not guaranteed.
       The Scalar struct holds an integer s < 2^{255} which represents an element of Z modulo the group order n.

``` Text
Owner has RAID_ID

 - RAID_ID (from DNS TXT record: "RYqMMuSmBZFQkgp"

Owner sign RAID_ID

 - Secret Key (re-used):                     "29bb078b7b2b01e62dd684cd20742b510ece6175fa58d7a79cceeefe5297a804"
 - Public Key (P):                           "ca469346d7643336c19155fdf5c6500a5232525ce4eba7e4db757639159e9861"
 - Secret Nonce (new):                       "ba557a86b110b3ef17a86d82d4cbbdcb0b350db40c5a92b7ed67427d0fd18f0f"
 - Public Nonce (R):                         "aec9ef137994f1750bb53387116830b691b871e4741387d1fa277b7b6c0e3462"
 - Challenge: e_signer_hash=H(R|P|RAID_ID)   "325755fffeaa3021c46bddc04bbc4e2fd584a30d5caeed311c7e22eb19b72104"
 - RAID_ID Signature (s):                    "23f2363a2302426ada8a5c004d6b3e76f63a78d230c7d6aaccb010adbcf9af0b"

Verifier check signature, using (s,R,P,RAID_ID) from DNS TXT record

 - RAID_ID Pub Sig (S=s·G):                  "fc0167f922a640d4e2f989b8d1374ac1f04d8e13a3083d3ff5907ce92763f26f"
 - Challenge: e_verifier_hash=H(R|P|RAID_ID) "325755fffeaa3021c46bddc04bbc4e2fd584a30d5caeed311c7e22eb19b72104"
 - Challenge: e_verifier_mod_n:              "325755fffeaa3021c46bddc04bbc4e2fd584a30d5caeed311c7e22eb19b72104"
 - Assert: s·G = R + e_verifier_mod_n·P
 - RAID_ID Signature is valid!

Additional asserts, for testing

 - Assert: e_signer_hash = e_verifier_hash
 - Recalculation of hashed challenge is valid!
 - Assert: R + e_signer_mod_n·P = R + e_verifier_mod_n·P
 - Equation is valid!
```

``` Text
Owner has RAID_ID

 - RAID_ID (from DNS TXT record: "RYqMMuSmBZFQkgp"

Owner sign RAID_ID

 - Secret Key (re-used):                     "29bb078b7b2b01e62dd684cd20742b510ece6175fa58d7a79cceeefe5297a804"
 - Public Key (P):                           "ca469346d7643336c19155fdf5c6500a5232525ce4eba7e4db757639159e9861"
 - Secret Nonce (new):                       "66851576f7f858827a87d671dc0ef678e98ec5f58d6d6e36b8b522582be4a603"
 - Public Nonce (R):                         "36bea71e04ba9fe3ad75d806046117d86edbc4d285249176159a11f40caeeb5c"
 - Challenge: e_signer_hash=H(R|P|RAID_ID)   "f6a449fa14f1ab9c9027da02b9814ce986cadae0174207d8301274c898074895"
 - RAID_ID Signature (s):                    "f62c78a058705cab6beae5a61fe68976445944e09fc358f75cd808db74acff0e"

Verifier check signature, using (s,R,P,RAID_ID) from DNS TXT record

 - RAID_ID Pub Sig (S=s·G):                  "608045c0cfe40744dcd42a7eda82fd9e69c969ca33224f5a043457aea2aead59"
 - Challenge: e_verifier_hash=H(R|P|RAID_ID) "f6a449fa14f1ab9c9027da02b9814ce986cadae0174207d8301274c898074895"
 - Challenge: e_verifier_mod_n:              "a131a5b52775068407a42548e5b8752d86cadae0174207d8301274c898074805"
 - Assert: s·G = R + e_verifier_mod_n·P
 - RAID_ID Signature is valid!

Additional asserts, for testing

 - Assert: e_signer_hash = e_verifier_hash
 - Recalculation of hashed challenge is valid!
 - Assert: R + e_signer_mod_n·P = R + e_verifier_mod_n·P
 - Equation is valid!
```