import pytest

from app.security.crypto import CryptoError, FieldContext, Vault, generate_master_key


@pytest.fixture()
def vault():
    return Vault(generate_master_key())


def test_roundtrip(vault):
    ctx = FieldContext("indicators", "value", "row-1")
    sealed = vault.seal("evil.example.com", ctx)
    assert "evil.example.com" not in sealed
    assert vault.open(sealed, ctx) == "evil.example.com"


def test_none_passes_through(vault):
    ctx = FieldContext("t", "c", "r")
    assert vault.seal(None, ctx) is None
    assert vault.open(None, ctx) is None


def test_same_plaintext_encrypts_differently(vault):
    ctx = FieldContext("t", "c", "r")
    assert vault.seal("same", ctx) != vault.seal("same", ctx)


def test_ciphertext_cannot_move_between_fields(vault):
    sealed = vault.seal("secret", FieldContext("users", "email", "row-1"))
    with pytest.raises(CryptoError):
        vault.open(sealed, FieldContext("users", "email", "row-2"))
    with pytest.raises(CryptoError):
        vault.open(sealed, FieldContext("users", "mfa_secret", "row-1"))


def test_tampering_is_detected(vault):
    ctx = FieldContext("t", "c", "r")
    sealed = vault.seal("payload", ctx)
    head, _, tail = sealed.rpartition(".")
    flipped = tail[:-2] + ("AA" if not tail.endswith("AA") else "BB")
    with pytest.raises(CryptoError):
        vault.open(f"{head}.{flipped}", ctx)


def test_another_key_cannot_open(vault):
    ctx = FieldContext("t", "c", "r")
    sealed = vault.seal("classified", ctx)
    with pytest.raises(CryptoError):
        Vault(generate_master_key()).open(sealed, ctx)


def test_blind_index_is_stable_and_case_insensitive(vault):
    a = vault.blind_index("Analyst@Example.com ", "user-email")
    b = vault.blind_index("analyst@example.com", "user-email")
    assert a == b
    assert a != vault.blind_index("analyst@example.com", "indicator")
    assert "analyst" not in a


def test_rewrap_preserves_plaintext(vault):
    ctx = FieldContext("t", "c", "r")
    sealed = vault.seal("rotate-me", ctx)
    new_key = generate_master_key()
    moved = vault.rewrap(sealed, ctx, new_key)
    assert Vault(new_key).open(moved, ctx) == "rotate-me"
    with pytest.raises(CryptoError):
        vault.open(moved, ctx)


def test_short_master_key_rejected():
    with pytest.raises(CryptoError):
        Vault("c2hvcnQ=")
