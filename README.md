# curveauth-py

A lightweight Python library for elliptic curve cryptography (ECC) focused on digital signatures, key handling, and secure token generation. Designed for systems where clients generate and sign messages using ECC keys, and the backend verifies them.

## Features

- Generate ECC public/private key pairs (P-256)
- Serialize keys to PEM or base64-encoded formats
- Sign and verify messages using ECDSA + SHA-256
- Export/import raw base64-encoded public keys (uncompressed X9.62)
- Generate random challenges for signature verification
- Generate secure API keys (base64 or hex, with optional prefixing)

## Example

```python
from curveauth.keys import ECCKeyPair
from curveauth.signatures import sign_message, verify_signature
from curveauth.challenge import generate_challenge
from curveauth.api_keys import generate_api_key

# Generate key pair
keypair = ECCKeyPair.generate()

# Sign a challenge
challenge = generate_challenge()
signature = sign_message(challenge, keypair.private_pem().decode("utf-8"))

# Verify the signature
pub_key_pem = keypair.public_pem().decode("utf-8")
assert verify_signature(challenge, signature, pub_key_pem)

# Generate a prefixed API key
api_key = generate_api_key(prefix="curveauth")
```
