import string

import pytest

from secrets_vault.generate import PRESETS, generate


def test_presets_tuple():
    assert PRESETS == ("urlsafe", "hex", "alphanum", "ascii")


def test_hex():
    v = generate("hex", 32)
    assert len(v) == 64
    assert set(v) <= set(string.hexdigits.lower())


def test_alphanum_length_is_chars():
    v = generate("alphanum", 40)
    assert len(v) == 40
    assert v.isalnum()


def test_ascii_avoids_quote_chars():
    v = generate("ascii", 200)
    assert not set(v) & set("\"'\\`$ ")


def test_unique():
    assert generate() != generate()


def test_errors():
    with pytest.raises(ValueError):
        generate("nope")
    with pytest.raises(ValueError):
        generate("hex", 0)
