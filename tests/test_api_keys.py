from curveauth.api_keys import generate_api_key

def test_api_key_base64():
    key = generate_api_key(length=32, format="base64")
    assert isinstance(key, str)
    assert len(key) >= 43  # base64 length for 32 bytes

def test_api_key_hex():
    key = generate_api_key(length=16, format="hex")
    assert isinstance(key, str)
    assert len(key) == 32  # 2 chars per byte

def test_api_key_base64_with_prefix():
    key = generate_api_key(length=32, format="base64", prefix="api")
    assert key.startswith("api_")
    assert isinstance(key, str)

def test_api_key_hex_with_prefix():
    key = generate_api_key(length=16, format="hex", prefix="custom")
    assert key.startswith("custom_")
    assert isinstance(key, str)

def test_api_key_invalid_format():
    try:
        generate_api_key(format="binary")
        assert False, "Expected ValueError"
    except ValueError:
        pass

if __name__ == "__main__":
    test_api_key_base64()
    test_api_key_hex()
    test_api_key_base64_with_prefix()
    test_api_key_hex_with_prefix()
    test_api_key_invalid_format()
    print("All API key tests passed.")
