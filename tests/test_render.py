import pytest

from secrets_vault.render import render


def test_dotenv_plain_and_quoted():
    out = render({"B_KEY": 'has "quotes" and spaces', "A_KEY": "simple-123"})
    lines = out.splitlines()
    assert lines[0] == "# managed by secrets-vault"
    assert lines[1] == "A_KEY=simple-123"                       # sorted, unquoted
    assert lines[2] == 'B_KEY="has \\"quotes\\" and spaces"'
    assert out.endswith("\n")


def test_env_format_always_quotes():
    out = render({"A": "simple"}, fmt="env")
    assert 'A="simple"' in out


def test_backslash_escaped():
    out = render({"A": "back\\slash"})
    assert 'A="back\\\\slash"' in out


def test_unknown_format():
    with pytest.raises(ValueError):
        render({}, fmt="yaml")


def test_trailing_newline_value_is_quoted_and_escaped():
    out = render({"A": "token\n"})
    assert 'A="token\\n"' in out
    lines = out.splitlines()
    assert len(lines) == 2  # header + one KEY line, no stray blank line


def test_interior_newline_escaped():
    out = render({"A": "line1\nline2"})
    assert 'A="line1\\nline2"' in out
