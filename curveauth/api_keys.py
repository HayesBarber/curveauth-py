"""
Generate API keys using random bytes.
Supports base64 and hex encoding with optional prefixing.
"""
import os
import base64

def generate_api_key(length: int = 32, format: str = "base64", prefix: str = None) -> str:
    """
    Generate an API key.

    :param length: Number of random bytes.
    :param format: Output format: 'base64', 'hex'.
    :param prefix: Optional prefix to prepend to the encoded key.
    :return: API key as a string.
    """
    raw = os.urandom(length)

    if format == "base64":
        key = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")
    elif format == "hex":
        key = raw.hex()
    else:
        raise ValueError("Unsupported format. Use 'base64', 'hex', or 'structured'.")
    
    if prefix is not None:
        return f"{prefix}_{key}"
    
    return key
