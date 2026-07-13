"""CSPRNG secret generation (stdlib `secrets`). Length = bytes of entropy
for urlsafe/hex, output characters for alphanum/ascii."""
import secrets
import string

PRESETS = ("urlsafe", "hex", "alphanum", "ascii")

_ALPHANUM = string.ascii_letters + string.digits
# printable ASCII minus space and chars that fight quoting: " ' \ ` $
_ASCII = "".join(c for c in (string.ascii_letters + string.digits + string.punctuation)
                 if c not in "\"'\\`$")


def generate(preset: str = "urlsafe", length: int = 32) -> str:
    if length < 1:
        raise ValueError("length must be >= 1")
    if preset == "urlsafe":
        return secrets.token_urlsafe(length)
    if preset == "hex":
        return secrets.token_hex(length)
    if preset == "alphanum":
        return "".join(secrets.choice(_ALPHANUM) for _ in range(length))
    if preset == "ascii":
        return "".join(secrets.choice(_ASCII) for _ in range(length))
    raise ValueError(f"unknown preset: {preset!r} (choose from {', '.join(PRESETS)})")
