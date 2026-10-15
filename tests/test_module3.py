"""Tests for Module 3 — Center Authentication (PKI / mTLS)."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from module3_center_auth.pki_setup import (
    generate_ca,
    issue_center_cert,
    save_cert_bundle,
)
from module3_center_auth.mtls_auth import authenticate_center


def test_generate_ca():
    ca_key, ca_cert = generate_ca()

    assert ca_key.public_key().public_numbers() == (
        ca_cert.public_key().public_numbers()
    )
    assert ca_cert.subject == ca_cert.issuer
    assert ca_cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value.ca is True


def test_issue_center_certificate():
    ca_key, ca_cert = generate_ca()
    center_key, center_cert = issue_center_cert(
        "CENTER-001", ca_key, ca_cert
    )

    assert center_key.public_key().public_numbers() == (
        center_cert.public_key().public_numbers()
    )
    assert center_cert.issuer == ca_cert.subject
    assert center_cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value == "CENTER-001"
    assert ExtendedKeyUsageOID.CLIENT_AUTH in (
    center_cert.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value
)


def test_authenticate_valid_center_certificate():
    ca_key, ca_cert = generate_ca()
    _, center_cert = issue_center_cert("CENTER-001", ca_key, ca_cert)

    assert authenticate_center(center_cert, ca_cert) is True


def test_reject_certificate_signed_by_another_ca():
    _, trusted_ca = generate_ca()
    other_ca_key, other_ca = generate_ca()
    _, foreign_cert = issue_center_cert(
        "CENTER-002", other_ca_key, other_ca
    )

    assert authenticate_center(foreign_cert, trusted_ca) is False


def test_reject_empty_center_id():
    ca_key, ca_cert = generate_ca()

    with pytest.raises(ValueError):
        issue_center_cert("   ", ca_key, ca_cert)


def test_save_certificate_bundle(tmp_path):
    ca_key, ca_cert = generate_ca()
    center_key, center_cert = issue_center_cert(
        "CENTER-001", ca_key, ca_cert
    )

    save_cert_bundle(
        "CENTER-001", center_key, center_cert, str(tmp_path)
    )

    key_path = tmp_path / "CENTER-001.key.pem"
    cert_path = tmp_path / "CENTER-001.cert.pem"

    assert key_path.exists()
    assert cert_path.exists()

    loaded_key = serialization.load_pem_private_key(
        key_path.read_bytes(), password=None
    )
    loaded_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())

    assert loaded_key.public_key().public_numbers() == (
        loaded_cert.public_key().public_numbers()
    )
