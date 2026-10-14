"""The DER walker against certificates cryptography made and ones built by hand."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from fiberd._testtable import table
from fiberd.client import _der, _testhome


def _tlv(tag: int, body: bytes) -> bytes:
    """One DER element, with the shortest length form."""
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    size = (n.bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + n.to_bytes(size, "big") + body


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


SPKI = _seq(_seq(b"\x06\x03\x2a\x03\x04"), b"\x03\x02\x00\xff")
INTEGER = b"\x02\x01\x07"
NAME = _seq(b"")
VERSION = b"\xa0\x03\x02\x01\x02"


def _v1_cert(spki: bytes = SPKI) -> bytes:
    """A certificate without the optional version, the X.509 v1 shape, with the signature left empty."""
    return _seq(_seq(INTEGER, _seq(b""), NAME, _seq(b""), NAME, spki), _seq(b""), b"\x03\x01\x00")


def _signed(key) -> bytes:
    """A self-signed certificate over key, to see the walker past bigger keys and other algorithms."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "k")])
    now = datetime.datetime.now(datetime.timezone.utc)
    b = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
    b = b.not_valid_before(now).not_valid_after(now + datetime.timedelta(hours=1))
    cert = b.sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _spki_of(der: bytes) -> bytes:
    return x509.load_der_x509_certificate(der).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


EC = _testhome.issue("ec").der
RSA = _signed(rsa.generate_private_key(public_exponent=65537, key_size=2048))
ED = _signed(ed25519.Ed25519PrivateKey.generate())

WALK = [
    # the certificate, the SubjectPublicKeyInfo wanted or the error text wanted
    ("a P-256 certificate", EC, _spki_of(EC)),
    ("an RSA certificate, whose lengths take two bytes", RSA, _spki_of(RSA)),
    ("an Ed25519 certificate", ED, _spki_of(ED)),
    ("a v1 certificate without the version element", _v1_cert(), SPKI),
    ("empty", b"", "truncated at byte 0"),
    ("not a SEQUENCE", b"\x02\x01\x07", "is not a SEQUENCE"),
    ("a length past the end", b"\x30\x10\x30\x02", "runs past the end"),
    ("an indefinite length", b"\x30\x80\x00\x00", "indefinite length"),
    ("a length of five bytes", b"\x30\x85\x00\x00\x00\x00\x01", "bad length"),
    ("a tbsCertificate that ends before the key", _seq(_seq(INTEGER, _seq(b""), NAME)), "ends before subjectPublicKeyInfo"),
    ("a key that is not a SEQUENCE", _v1_cert(spki=b"\x04\x01\x00"), "is not a SEQUENCE"),
    ("the certificate cut inside the key", EC[: len(EC) - len(_spki_of(EC)) - 40], "runs past the end"),
]


@table(WALK)
def test_spki(name, f0, f1):
    if isinstance(f1, bytes):
        assert _der.spki(f0) == f1
    else:
        with pytest.raises(_der.DERError, match=f1):
            _der.spki(f0)


PINS = [
    # the SubjectPublicKeyInfo, its pin
    ("the empty input is the known SHA-256 of nothing, base64url without padding", b"", "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"),
    ("a key is 43 characters of the url alphabet", SPKI, None),
]


@table(PINS)
def test_pin(name, f0, f1):
    got = _der.pin(f0)
    if f1 is not None:
        assert got == f1
    assert len(got) == 43 and "=" not in got and "+" not in got and "/" not in got
