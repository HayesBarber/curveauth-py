from curveauth.challenge import generate_challenge

def test_generate_base64_challenge():
    challenge = generate_challenge(length=32, encoding="base64")
    assert isinstance(challenge, str)
    assert len(challenge) >= 43  # base64 encoded 32 bytes without padding

def test_generate_hex_challenge():
    challenge = generate_challenge(length=16, encoding="hex")
    assert isinstance(challenge, str)
    assert len(challenge) == 32  # 2 hex chars per byte

def test_generate_invalid_encoding():
    try:
        generate_challenge(length=16, encoding="binary")
        assert False, "Expected ValueError"
    except ValueError:
        pass

if __name__ == "__main__":
    test_generate_base64_challenge()
    test_generate_hex_challenge()
    test_generate_invalid_encoding()
    print("All challenge tests passed.")
