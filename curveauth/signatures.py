import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from curveauth.keys import ECCKeyPair

def sign_message(message: str, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Not an ECC private key")
    signature = private_key.sign(
        message.encode("utf-8"),
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode("utf-8")

def verify_signature(message: str, signature_b64: str, public_key_str: str, is_raw_key: bool = False) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        if is_raw_key:
            public_key = ECCKeyPair.load_public_key_raw_base64(public_key_str)
        else:
            public_key = serialization.load_pem_public_key(public_key_str.encode("utf-8"))

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Not an ECC public key")

        public_key.verify(
            signature,
            message.encode("utf-8"),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except (InvalidSignature, ValueError, base64.binascii.Error):
        return False
