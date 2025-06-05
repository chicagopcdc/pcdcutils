from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pytest
from pcdcutils.gen3 import Gen3RequestManager, SignaturePayload
import os
import logging

# openssl genpkey -algorithm RSA -out PRIVATE_NAME.pem -pkeyopt rsa_keygen_bits:2048
# openssl rsa -pubout -in PRIVATE_NAME.pem -out PUB_NAME.pem
# To run the tests, create a keys directory in the tests folder and create key pairs private/public_key1 and 2.pem


def test_successful_make_sig():
    payload = SignaturePayload(
        method="POST",
        path="/test/path",
        body='{"key": "value"}',  # Any string like body = "aaaaa"
    )
    pri_key_path = os.getcwd() + "/tests/keys/private_key1.pem"
    keyfile = open(pri_key_path, "r").read()
    pri_key = RSA.import_key(keyfile)

    g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "service"})
    signature = g3.make_gen3_signature(payload, {"SERVICE_PRIVATE_KEY": pri_key})

    assert isinstance(signature, str)
    assert len(signature) > 10


def test_bad_make_sig():
    payload = SignaturePayload(
        method="POST",
        path="/test/path",
        body='{"key": "value"}',  # Any string like body = "aaaaa"
    )
    bad_key_path = os.getcwd() + "/tests/keys/public_key1.pem"
    keyfile = open(bad_key_path, "r").read()
    bad_key = RSA.import_key(keyfile)

    g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "service"})
    with pytest.raises(TypeError) as ex:
        g3.make_gen3_signature(payload, {"SERVICE_PRIVATE_KEY": bad_key})

    assert "This is not a private key" in str(ex.value)


def test_successful_validate_sig():
    payload = SignaturePayload(
        method="POST",
        path="/test/path",
        body='{"key": "value"}',  # Any string like body = "aaaaa"
    )
    pri_key_path = os.getcwd() + "/tests/keys/private_key1.pem"
    keyfile = open(pri_key_path, "r").read()
    pri_key = RSA.import_key(keyfile)

    g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "service"})
    signature = g3.make_gen3_signature(payload, {"SERVICE_PRIVATE_KEY": pri_key})

    signed_g3 = Gen3RequestManager(
        {"Signature": "signature " + signature, "Gen3-Service": "service"}
    )

    pub_key_path = os.getcwd() + "/tests/keys/public_key1.pem"
    keyfile = open(pub_key_path, "r").read()
    pub_key = RSA.import_key(keyfile)

    assert signed_g3.valid_gen3_signature(payload, {"SERVICE_PUBLIC_KEY": pub_key})


def test_bad_validate_sig():
    payload = SignaturePayload(
        method="POST",
        path="/test/path",
        body='{"key": "value"}',  # Any string like body = "aaaaa"
    )
    pri_key_path = os.getcwd() + "/tests/keys/private_key2.pem"
    keyfile = open(pri_key_path, "r").read()
    pri_key = RSA.import_key(keyfile)

    g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "service"})
    signature = g3.make_gen3_signature(payload, {"SERVICE_PRIVATE_KEY": pri_key})

    signed_g3 = Gen3RequestManager(
        {"Signature": "signature " + signature, "Gen3-Service": "service"}
    )

    pub_key_path = os.getcwd() + "/tests/keys/public_key1.pem"
    keyfile = open(pub_key_path, "r").read()
    pub_key = RSA.import_key(keyfile)

    assert (
        signed_g3.valid_gen3_signature(payload, {"SERVICE_PUBLIC_KEY": pub_key})
        == False
    )


def test_make_gen3_signature_with_signature_payload():
    payload = SignaturePayload(
        method="POST", path="/admin/users/selected", body='{"usernames": ["someone"]}'
    )

    key = RSA.generate(2048)

    g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "test-service"})
    config = {"TEST-SERVICE_PRIVATE_KEY": key}

    signature = g3.make_gen3_signature(payload, config)

    assert isinstance(signature, str)
    assert len(signature) > 10


def test_signature_logs(caplog):
    payload = SignaturePayload(
        method="POST", path="/admin/users/selected", body='{"usernames": ["someone"]}'
    )

    test_key = RSA.generate(2048)

    g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "test-service"})
    config = {"TEST-SERVICE_PRIVATE_KEY": test_key}

    # Checking caplog is actually captured.
    with caplog.at_level(logging.INFO):
        signature = g3.make_gen3_signature(payload, config)

    # Check for the log message
    assert any(
        "signed payload of length" in record.message for record in caplog.records
    )
