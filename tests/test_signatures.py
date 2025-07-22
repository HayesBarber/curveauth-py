from curveauth.signatures import sign_message, verify_signature
from curveauth.keys import ECCKeyPair

def test_sign_verify_pem():
    keypair = ECCKeyPair.generate()
    message = "test message"
    priv_pem = keypair.private_pem()
    pub_pem = keypair.public_pem().decode("utf-8")

    signature_b64 = sign_message(message, priv_pem.decode("utf-8"))
    assert isinstance(signature_b64, str)
    assert verify_signature(message, signature_b64, pub_pem) is True
    assert verify_signature(message + "x", signature_b64, pub_pem) is False

def test_sign_verify_raw_pubkey():
    keypair = ECCKeyPair.generate()
    message = "another message"
    priv_pem = keypair.private_pem()
    pub_raw_b64 = keypair.public_key_raw_base64()

    signature_b64 = sign_message(message, priv_pem.decode("utf-8"))
    assert isinstance(signature_b64, str)
    assert verify_signature(message, signature_b64, pub_raw_b64, is_raw_key=True) is True
    assert verify_signature(message + "y", signature_b64, pub_raw_b64, is_raw_key=True) is False

def test_verify_signature_errors():
    message = "test"
    bad_sig = "not_base64"
    bad_pem = "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----"
    bad_raw = "not_base64_raw_key"

    # Invalid base64 signature
    assert verify_signature(message, bad_sig, bad_pem) is False

    # Invalid PEM public key
    keypair = ECCKeyPair.generate()
    valid_sig = sign_message(message, keypair.private_pem().decode("utf-8"))
    assert verify_signature(message, valid_sig, bad_pem) is False

    # Invalid base64 raw key
    assert verify_signature(message, valid_sig, bad_raw, is_raw_key=True) is False

    # Garbage input as public key
    assert verify_signature(message, valid_sig, "12345") is False

if __name__ == "__main__":
    test_sign_verify_pem()
    test_sign_verify_raw_pubkey()
    test_verify_signature_errors()
    print("All signature tests passed.")
