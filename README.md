# crypto_playpen

Using Tari Project's crypto::ristretto to create and verify signatures on a RAID_ID.

Note: `e_verifier_hash` may be equal to `e_verifier_on_G` as shown below, but this is not guaranteed.

``` Text
Owner has RAID_ID

 - RAID_ID (from DNS TXT record: "RYqMMuSmBZFQkgp"

Owner sign RAID_ID

 - Secret Key (re-used):                     "29bb078b7b2b01e62dd684cd20742b510ece6175fa58d7a79cceeefe5297a804"
 - Public Key (P):                           "ca469346d7643336c19155fdf5c6500a5232525ce4eba7e4db757639159e9861"
 - Secret Nonce (new):                       "98ba8f8ef3d506660dcda4458ccb87bb40875835c4e2d265a34be84d57fd3e0c"
 - Public Nonce (R):                         "dcf3f1a8e8c48f35b4fe04d1d92990fdf949e5dda5132692e0472e7d5418a514"
 - Challenge: e_signer_hash=H(R|P|RAID_ID)   "d3cfe3febbb9bca233e5b5821dde8148f0935d886e327389cd1737f15754e900"
 - RAID_ID Signature (s):                    "ca491c261027b780dd80dbd8f2e7a0f7ed5f10ed2bb8dc2d702c6fa716da610a"

Verifier check signature, using (s,R,P,RAID_ID) from DNS TXT record

 - RAID_ID Pub Sig (S=s·G):                  "62371222aebcc0a52ff6fbd268a7038560ee22d488fa7b91fac64c7ee82f0c56"
 - Challenge: e_verifier_hash=H(R|P|RAID_ID) "d3cfe3febbb9bca233e5b5821dde8148f0935d886e327389cd1737f15754e900"
 - e_verifier_on_G:                          "d3cfe3febbb9bca233e5b5821dde8148f0935d886e327389cd1737f15754e900"
 - Assert: s·G = R + e_verifier_on_G·P
 - RAID_ID Signature is valid!

Additional asserts, for testing

 - Assert: e_signer_hash = e_verifier_hash
 - Recalculation of hashed challenge is valid!
 - Assert: R + e_signer_on_G·P = R + e_verifier_on_G·P
 - Equation is valid!
```

``` Text
Owner has RAID_ID

 - RAID_ID (from DNS TXT record: "RYqMMuSmBZFQkgp"

Owner sign RAID_ID

 - Secret Key (re-used):                     "29bb078b7b2b01e62dd684cd20742b510ece6175fa58d7a79cceeefe5297a804"
 - Public Key (P):                           "ca469346d7643336c19155fdf5c6500a5232525ce4eba7e4db757639159e9861"
 - Secret Nonce (new):                       "5d64e67971cacb60e031accc0eea90fb92b2de5f9c0755412b20275035c20e0f"
 - Public Nonce (R):                         "944eab828c73d475b104a8a60291052824a60762daddfb521a80bfc910980732"
 - Challenge: e_signer_hash=H(R|P|RAID_ID)   "29c49637d23201ee302e38be63691e12be30fd1503bc671c62d37aa094aa851c"
 - RAID_ID Signature (s):                    "fc2ccb773f696846f6e107ff9ccd08c11ee9a4075cfb27be8dea5cc76f73d00a"

Verifier check signature, using (s,R,P,RAID_ID) from DNS TXT record

 - RAID_ID Pub Sig (S=s·G):                  "a2f0121721d2bd3d4e1d41524dfbc71028a195fc02bf37b8a9456603ccbe0226"
 - Challenge: e_verifier_hash=H(R|P|RAID_ID) "29c49637d23201ee302e38be63691e12be30fd1503bc671c62d37aa094aa851c"
 - e_verifier_on_G:                          "3cf0a0dab7cfee955a91401b856f3ffdbd30fd1503bc671c62d37aa094aa850c"
 - Assert: s·G = R + e_verifier_on_G·P
 - RAID_ID Signature is valid!

Additional asserts, for testing

 - Assert: e_signer_hash = e_verifier_hash
 - Recalculation of hashed challenge is valid!
 - Assert: R + e_signer_on_G·P = R + e_verifier_on_G·P
 - Equation is valid!
```