import sys
import os
from pathlib import Path

current_test_dir = Path(__file__).resolve().parent
project_root = current_test_dir.parent

root_str = str(project_root)
if root_str not in sys.path:
    sys.path.insert(0, root_str)

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from micropki.crypto_utils import read_passphrase_from_file
from micropki.ca import parse_subject_name, generate_key_pair, create_self_signed_cert


def test_read_passphrase():
    test_file = Path("test_pass.tmp")
    test_file.write_bytes(b"SecretPass\n")

    try:
        pwd = read_passphrase_from_file(str(test_file))
        assert pwd == b"SecretPass"
    finally:
        if test_file.exists():
            test_file.unlink()


def test_subject_parsing():
    name = parse_subject_name("/CN=Test CA,O=TestOrg,C=US")

    name_list = list(name)

    assert len(name_list) == 3

    first_attr = name_list[0]
    assert first_attr.oid._name == "commonName"
    assert first_attr.value == "Test CA"


def test_key_generation_rsa():
    key = generate_key_pair("rsa", 4096)
    assert key.key_size == 4096


def test_key_generation_ecc():
    key = generate_key_pair("ecc", 384)
    assert key.curve.name == "secp384r1"


def test_cert_extensions():
    key = generate_key_pair("rsa", 4096)
    subject = parse_subject_name("CN=UnitTest")
    cert = create_self_signed_cert(key, subject, 1)

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True
    assert bc.critical is True

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.value.key_cert_sign is True
    assert ku.critical is True