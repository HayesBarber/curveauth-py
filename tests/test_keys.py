from curveauth.keys import ECCKeyPair

def test_keypair_pem_cycle():
    # Generate new key pair
    keypair = ECCKeyPair.generate()

    # Export public key to PEM and reload it
    public_pem = keypair.public_pem()
    loaded_pub = ECCKeyPair.load_public_pem(public_pem)

    assert loaded_pub.public_numbers() == keypair._public_key.public_numbers()

    # Export private key to PEM and reload it
    private_pem = keypair.private_pem()
    loaded_keypair = ECCKeyPair.load_private_pem(private_pem)

    assert loaded_keypair._private_key.private_numbers() == keypair._private_key.private_numbers()

def test_keypair_raw_base64_cycle():
    keypair = ECCKeyPair.generate()

    raw_b64 = keypair.public_key_raw_base64()
    loaded_pub = ECCKeyPair.load_public_key_raw_base64(raw_b64)

    assert loaded_pub.public_numbers() == keypair._public_key.public_numbers()

if __name__ == "__main__":
    test_keypair_pem_cycle()
    test_keypair_raw_base64_cycle()
    print("All tests passed.")
