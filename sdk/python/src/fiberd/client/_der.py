"""The SubjectPublicKeyInfo of a DER certificate, and its pin.

The ssl module hands back the peer certificate as DER and offers no hook
during the handshake, so the handoff pin is checked after it by walking
the certificate to its SubjectPublicKeyInfo. A Certificate is SEQUENCE {
tbsCertificate SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
issuer, validity, subject, subjectPublicKeyInfo, ... }, ... }, and the
walk needs only tags and lengths.
"""

from __future__ import annotations

import base64
import hashlib

SEQUENCE = 0x30
VERSION = 0xA0


class DERError(ValueError):
    """The bytes are not a DER certificate the walker can read."""


def _tlv(der: bytes, at: int) -> tuple[int, int, int]:
    """The tag, the start of the value and the end of the element at `at`."""
    if at + 2 > len(der):
        raise DERError(f"truncated at byte {at}")
    tag, first = der[at], der[at + 1]
    at += 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DERError(f"indefinite length at byte {at - 1}")
    else:
        n = first & 0x7F
        if n > 4 or at + n > len(der):
            raise DERError(f"bad length at byte {at - 1}")
        length = int.from_bytes(der[at:at + n], "big")
        at += n
    if at + length > len(der):
        raise DERError(f"element at byte {at} runs past the end")
    return tag, at, at + length


def _enter(der: bytes, at: int) -> tuple[int, int]:
    """The value bounds of the SEQUENCE at `at`."""
    tag, start, end = _tlv(der, at)
    if tag != SEQUENCE:
        raise DERError(f"tag {tag:#x} at byte {at} is not a SEQUENCE")
    return start, end


def spki(cert_der: bytes) -> bytes:
    """The DER SubjectPublicKeyInfo of a DER certificate."""
    at, _ = _enter(cert_der, 0)
    at, tbs_end = _enter(cert_der, at)
    tag, _, end = _tlv(cert_der, at)
    if tag == VERSION:
        at = end
    # serialNumber, signature, issuer, validity and subject come before it.
    for _ in range(5):
        if at >= tbs_end:
            raise DERError("tbsCertificate ends before subjectPublicKeyInfo")
        _, _, at = _tlv(cert_der, at)
    tag, _, end = _tlv(cert_der, at)
    if tag != SEQUENCE or end > tbs_end:
        raise DERError(f"subjectPublicKeyInfo at byte {at} is not a SEQUENCE")
    return cert_der[at:end]


def pin(spki_der: bytes) -> str:
    """The base64url SHA-256 of a SubjectPublicKeyInfo, as CloneResponse.server_key_sha256 spells it."""
    return base64.urlsafe_b64encode(hashlib.sha256(spki_der).digest()).rstrip(b"=").decode()
