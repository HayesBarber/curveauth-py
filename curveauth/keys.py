from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class ECCKeyPair:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "ECCKeyPair":
        private_key = ec.generate_private_key(ec.SECP256R1())
        return cls(private_key)

    def private_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_pem(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def load_private_pem(pem_data: bytes) -> "ECCKeyPair":
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None,
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Not an ECC private key")
        return ECCKeyPair(private_key)

    @staticmethod
    def load_public_pem(pem_data: bytes) -> ec.EllipticCurvePublicKey:
        public_key = serialization.load_pem_public_key(pem_data)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Not an ECC public key")
        return public_key
