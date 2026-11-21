"""pytest configuration: make the project root importable and share expensive fixtures."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecc import ECCKeyPair  # noqa: E402
from rsa import generate_rsa_keypair  # noqa: E402


@pytest.fixture(scope="session")
def rsa_key():
    """RSA-2048 generated with the Sage prime search (fast enough for tests)."""
    return generate_rsa_keypair(2048, "sage")


@pytest.fixture(scope="session")
def rsa_key2():
    return generate_rsa_keypair(2048, "sage")


@pytest.fixture(scope="session")
def ecc_key():
    return ECCKeyPair.generate("P-256", "sage")


@pytest.fixture(scope="session")
def ecc_key2():
    return ECCKeyPair.generate("P-256", "sage")


# Messages shared by the encryption tests: binary, UTF-8, empty, and assorted lengths.
MESSAGES = [
    b"",
    b"a",
    "Hello, world".encode(),
    "UTF-8: café π ∑ 日本語 \U0001F512".encode("utf-8"),
    bytes(range(256)),
    b"\x00" * 100,
    b"x" * 1000,
    b"y" * 100_000,
]
