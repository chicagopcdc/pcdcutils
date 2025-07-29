import pytest
import requests
from unittest.mock import patch
from pcdcutils.gen3 import Gen3RequestManager, SignaturePayload
from pcdcutils.signature import SignatureManager
from pcdcutils.errors import KeyPathInvalidError
import os
import logging

# openssl genpkey -algorithm RSA -out PRIVATE_NAME.pem -pkeyopt rsa_keygen_bits:2048
# openssl rsa -pubout -in PRIVATE_NAME.pem -out PUB_NAME.pem
# To run the tests, create a keys directory in the tests folder and create key pairs private/public_key1 and 2.pem
# poetry run pytest -s tests/test_utils.py


def test_successful_make_sig():
    key_path = os.getcwd() + "/tests/keys/private_key1.pem"
    url = "http://localhost:9443/test/path"
    body = '{"key": "value"}'  # Any string like body = "aaaaa"
    jwt = "mock.jwt.token"  # Mock jwt
    test_service = "AMANUENSIS"  # TODO: We can populate with variable --service=...
    headers = {
        "Gen3-Service": test_service,
    }

    # Create payload object with an instance of SignaturePayload class
    payload = SignaturePayload(
        method="POST",
        path=url,
        headers=headers,
        body=body,
    )

    # Initializes an instance of Gen3RequestManager.
    g3rm = Gen3RequestManager(headers=headers)

    # Using PCDCUtils signatureManager instead of doing it manually.
    pri_key = SignatureManager(key_path).get_key()

    # Create signature with the method
    signature = g3rm.make_gen3_signature(
        payload, {f"{test_service}_PRIVATE_KEY": pri_key}
    )

    # Populate headers, addiing after signature, so payload.headers contains final signed headers
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = "bearer " + jwt
    headers["Signature"] = "signature " + signature

    # Mock requests.post, because no server at url variable
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"success": True}

        r = requests.post(url, data=body, headers=headers)

        assert r.status_code == 200
        assert r.json()["success"] is True

    # Test the signature itself
    assert isinstance(signature, str)
    assert len(signature) > 10
    print("Make Signature Success, signature length:", len(signature))


def test_bad_make_sig():
    key_path = os.getcwd() + "/tests/keys/wrong_key1.pem"
    url = "http://localhost:9443/test/path"
    body = '{"key": "value"}'  # Any string like body = "aaaaa"
    jwt = "mock.jwt.token"  # Mock jwt
    test_service = "AMANUENSIS"  # TODO: We can populate with variable --service=...
    headers = {
        "Gen3-Service": test_service,
    }

    # Create payload object with an instance of SignaturePayload class
    payload = SignaturePayload(
        method="POST",
        path=url,
        headers=headers,
        body=body,
    )

    # Initializes an instance of Gen3RequestManager.
    g3rm = Gen3RequestManager(headers=headers)

    # Now catch the error — INCLUDING the bad key load
    with pytest.raises(KeyPathInvalidError) as ex:
        # Using PCDCUtils signatureManager instead of doing it manually.
        pri_key = SignatureManager(key_path).get_key()

        # Create signature with the method
        signature = g3rm.make_gen3_signature(
            payload, {f"{test_service}_PRIVATE_KEY": pri_key}
        )

        # Populate headers, addiing after signature, so payload.headers contains final signed headers
        headers["Content-Type"] = "application/json"
        headers["Authorization"] = "bearer " + jwt
        headers["Signature"] = "signature " + signature

    # Verify the error message
    print("BAD KEY CHECK:", "key_path is not found or invalid" in str(ex.value))
    assert "key_path is not found or invalid" in str(ex.value)


def test_successful_validate_sig():
    key_path = os.getcwd() + "/tests/keys/private_key1.pem"
    pub_key_path = os.getcwd() + "/tests/keys/public_key1.pem"
    url = "http://localhost:9443/test/path"
    body = '{"key": "value"}'  # Any string like body = "aaaaa"
    jwt = "mock.jwt.token"  # Mock jwt
    test_service = "AMANUENSIS"  # TODO: We can populate with variable --service=...
    headers = {
        "Gen3-Service": test_service,
    }

    # Create payload object with an instance of SignaturePayload class
    payload = SignaturePayload(
        method="POST",
        path=url,
        headers=headers,
        body=body,
    )

    # Initializes an instance of Gen3RequestManager.
    g3rm = Gen3RequestManager(headers=headers)

    # Using PCDCUtils signatureManager instead of doing it manually.
    pri_key = SignatureManager(key_path).get_key()

    # Create signature with the method
    signature = g3rm.make_gen3_signature(
        payload, {f"{test_service}_PRIVATE_KEY": pri_key}
    )

    # Populate headers, addiing after signature, so payload.headers contains final signed headers
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = "bearer " + jwt
    headers["Signature"] = "signature " + signature

    # Mock requests.post, because no server at url variable
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"success": True}

        r = requests.post(url, data=body, headers=headers)

        assert r.status_code == 200
        assert r.json()["success"] is True

    # Validate the signature
    pub_key = SignatureManager(pub_key_path).get_key()

    assert g3rm.valid_gen3_signature(payload, {f"{test_service}_PUBLIC_KEY": pub_key})

    print("Signature validated successfully.")


def test_bad_validate_sig():
    key_path = os.getcwd() + "/tests/keys/private_key1.pem"
    wrong_pub_key_path = os.getcwd() + "/tests/keys/public_key2.pem"
    url = "http://localhost:9443/test/path"
    body = '{"key": "value"}'  # Any string like body = "aaaaa"
    jwt = "mock.jwt.token"  # Mock jwt
    test_service = "AMANUENSIS"  # TODO: We can populate with variable --service=...
    headers = {
        "Gen3-Service": test_service,
    }

    # Create payload object with an instance of SignaturePayload class
    payload = SignaturePayload(
        method="POST",
        path=url,
        headers=headers,
        body=body,
    )

    # Initializes an instance of Gen3RequestManager.
    g3rm = Gen3RequestManager(headers=headers)

    # Using PCDCUtils signatureManager instead of doing it manually.
    pri_key = SignatureManager(key_path).get_key()

    # Create signature with the method
    signature = g3rm.make_gen3_signature(
        payload, {f"{test_service}_PRIVATE_KEY": pri_key}
    )

    # Populate headers, addiing after signature, so payload.headers contains final signed headers
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = "bearer " + jwt
    headers["Signature"] = "signature " + signature

    # Mock requests.post, because no server at url variable
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"success": True}

        r = requests.post(url, data=body, headers=headers)

        assert r.status_code == 200
        assert r.json()["success"] is True

    # Validate the signature
    pub_key = SignatureManager(wrong_pub_key_path).get_key()

    assert not g3rm.valid_gen3_signature(
        payload, {f"{test_service}_PUBLIC_KEY": pub_key}
    )

    print("Signature NOT validated, the keys did not match up.")


def test_signature_logs_and_validation(caplog):
    key_path = os.getcwd() + "/tests/keys/private_key1.pem"
    pub_key_path = os.getcwd() + "/tests/keys/public_key1.pem"
    url = "http://localhost:9443/test/path"
    body = '{"key": "value"}'  # Any string like body = "aaaaa"
    jwt = "mock.jwt.token"  # Mock jwt
    test_service = "AMANUENSIS"  # TODO: We can populate with variable --service=...
    headers = {
        "Gen3-Service": test_service,
    }

    # Create payload object with an instance of SignaturePayload class
    payload = SignaturePayload(
        method="POST",
        path=url,
        headers=headers,
        body=body,
    )

    # Initializes an instance of Gen3RequestManager.
    g3rm = Gen3RequestManager(headers=headers)

    # Using PCDCUtils signatureManager instead of doing it manually.
    pri_key = SignatureManager(key_path).get_key()

    # Checking caplog is actually captured.
    with caplog.at_level(logging.INFO):

        # Create signature with the method
        signature = g3rm.make_gen3_signature(
            payload, {f"{test_service}_PRIVATE_KEY": pri_key}
        )

        # Populate headers, addiing after signature, so payload.headers contains final signed headers
        headers["Content-Type"] = "application/json"
        headers["Authorization"] = "bearer " + jwt
        headers["Signature"] = "signature " + signature

    # Validate the signature
    pub_key = SignatureManager(pub_key_path).get_key()

    assert g3rm.valid_gen3_signature(payload, {f"{test_service}_PUBLIC_KEY": pub_key})

    assert any(
        "signed payload of length" in record.message for record in caplog.records
    )

    print("Captured log messages:")
    for record in caplog.records:
        print(f"  {record.levelname}: {record.message}")

    print("Signature validated and expected log message found.")
