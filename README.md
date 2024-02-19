# tpke

This repository is an experimental implementation of decentralized threshold encryption and decryption.

## Architecture

- DKG - A decentralized key generation process where participants generate and share their local secret, to get a global public key for encryption and signature verification;
- TPKE - A use case where users encrypt something with global public key, and participants try to decrypt with their different pieces of secret;
- TSS - A use case where participants sign something with local secrets, and users verify the result with the global public key;
- DBFT - A use case that involves both TPKE and TSS to realize anti-MEV and true random numbers, locates in another [repo](https://github.com/txhsl/dbft-anti-mev).
