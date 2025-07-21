import base64
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

    def public_key_raw_base64(self) -> str:
        raw_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return base64.b64encode(raw_bytes).decode("utf-8")

    @staticmethod
    def load_public_key_raw_base64(b64_key: str) -> ec.EllipticCurvePublicKey:
        raw_bytes = base64.b64decode(b64_key)
        if len(raw_bytes) != 65 or raw_bytes[0] != 0x04:
            raise ValueError("Invalid uncompressed ECC public key format")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_bytes)
