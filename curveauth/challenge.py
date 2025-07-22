"""
Generate random challenges to be used when asking clients to sign a challenge.
Useful for authentication or key verification workflows.
"""
import os
import base64

def generate_challenge(length: int = 32, encoding: str = "base64") -> str:
    """
    Generate a cryptographic challenge of specified byte length.
    Encoding can be 'base64' or 'hex'.
    """
    raw = os.urandom(length)

    if encoding == "base64":
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")
    elif encoding == "hex":
        return raw.hex()
    else:
        raise ValueError("Unsupported encoding. Use 'base64' or 'hex'.")
