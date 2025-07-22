"""
ECC key handling utilities for key generation, serialization, and deserialization.
Supports both PEM and base64-encoded raw public key formats.
"""

import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class ECCKeyPair:
    """
    Encapsulates an elliptic curve private/public key pair using the SECP256R1 curve.
    Provides methods for generating keys, exporting/importing keys in PEM and base64 formats.
    """

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        """
        Initialize with an existing private key.
        """
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "ECCKeyPair":
        """
        Generate a new ECCKeyPair using the SECP256R1 curve.
        :return: ECCKeyPair instance with a new key pair.
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        return cls(private_key)

    def private_pem(self) -> bytes:
        """
        Export the private key in PEM format (unencrypted PKCS#8).
        :return: PEM-encoded private key bytes.
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_pem(self) -> bytes:
        """
        Export the public key in PEM format (SubjectPublicKeyInfo).
        :return: PEM-encoded public key bytes.
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def load_private_pem(pem_data: bytes) -> "ECCKeyPair":
        """
        Load a private key from PEM and return a new ECCKeyPair instance.
        :param pem_data: PEM-encoded private key bytes.
        :return: ECCKeyPair instance.
        """
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None,
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Not an ECC private key")
        return ECCKeyPair(private_key)

    @staticmethod
    def load_public_pem(pem_data: bytes) -> ec.EllipticCurvePublicKey:
        """
        Load a public key from PEM.
        :param pem_data: PEM-encoded public key bytes.
        :return: EllipticCurvePublicKey instance.
        """
        public_key = serialization.load_pem_public_key(pem_data)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Not an ECC public key")
        return public_key

    def public_key_raw_base64(self) -> str:
        """
        Export the public key in uncompressed point format (X962), base64-encoded.
        :return: Base64-encoded raw public key string.
        """
        raw_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return base64.b64encode(raw_bytes).decode("utf-8")

    @staticmethod
    def load_public_key_raw_base64(b64_key: str) -> ec.EllipticCurvePublicKey:
        """
        Load a public key from a base64-encoded uncompressed point.
        :param b64_key: Base64-encoded public key (65-byte format: 0x04 || X || Y).
        :return: EllipticCurvePublicKey instance.
        """
        raw_bytes = base64.b64decode(b64_key)
        if len(raw_bytes) != 65 or raw_bytes[0] != 0x04:
            raise ValueError("Invalid uncompressed ECC public key format")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_bytes)
