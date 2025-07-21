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

if __name__ == "__main__":
    test_sign_verify_pem()
    test_sign_verify_raw_pubkey()
    print("All signature tests passed.")
