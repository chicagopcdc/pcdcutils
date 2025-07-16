import pytest
import requests
from unittest.mock import patch
from pcdcutils.gen3 import Gen3RequestManager, SignaturePayload
from pcdcutils.signature import SignatureManager
from pcdcutils.errors import KeyPathInvalidError
import os
import logging
import time
from pcdcutils.client import FenceClientManager
import asyncio
import anyio

# openssl genpkey -algorithm RSA -out PRIVATE_NAME.pem -pkeyopt rsa_keygen_bits:2048
# openssl rsa -pubout -in PRIVATE_NAME.pem -out PUB_NAME.pem
# To run the tests, create a keys directory in the tests folder and create key pairs private/public_key1 and 2.pem
# poetry run pytest -s tests/test_utils.py

#reading variables from a file
def file_load_fence_env(path):
    env_vars = {}
    with open (path) as file:
        for line in file:
            if "=" in line :
                key, value = line.strip().split("=",1)
                env_vars[key] = value
    return env_vars
#"/tests/keys/fence/fence_keys.env"
env_key_path = os.getcwd() + "/tests/keys/fence_keys.env"
env = file_load_fence_env(env_key_path)

FAKE_FENCE_URL = env["FAKE_FENCE_URL"]
FAKE_CLIENT_ID = env["FAKE_CLIENT_ID"]
FAKE_CLIENT_SECRET = env["FAKE_CLIENT_SECRET"]


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






def test_fence_client_manager_success(monkeypatch):
    # We create a fake Gen3Auth class to avoid making real network requests.
    class FakeGen3Auth:
        def __init__(self, endpoint, client_credentials, client_scopes):
            # Save the inputs so we can check them if needed
            self.endpoint = endpoint
            self.client_credentials = client_credentials
            self.client_scopes = client_scopes
            # We set a fake access token value
            self._access_token = "fake-token"

        def get_access_token(self):
            # This returns the fake token instead of making a real API call
            return self._access_token

    # Replace (monkeypatch) the real Gen3Auth with our fake one inside FenceClientManager
    monkeypatch.setattr("pcdcutils.client.Gen3Auth", FakeGen3Auth)

    # Create a FenceClientManager instance using our test config values
    client = FenceClientManager(
        base_url=FAKE_FENCE_URL,
        client_id=FAKE_CLIENT_ID,
        client_secret=FAKE_CLIENT_SECRET,
    )

    # Run authenticate() — this should use our FakeGen3Auth and set the auth object
    client.authenticate()

    # Check that the client now says it's authenticated
    assert client.is_authenticated(), "client was not authenticated"

    # Get a token from our fake auth — should match our fake token value
    token = client.get_auth_token()
    assert token == "fake-token", "wrong token returned"

def test_fence_client_manager_invalid(monkeypatch):
    # Create a client without any credentials to simulate a misconfigured state
    client = FenceClientManager(base_url=None, client_id=None, client_secret=None)

    # Run authenticate() — since credentials are missing, this should not set auth
    client.authenticate()

    # Check that the client is not authenticated
    assert not client.is_authenticated()

    # Get token — because there's no auth, we expect an empty string (not an error)
    token = client.get_auth_token()
    assert token == ""

def test_fence_client_manager_timeout(monkeypatch):
    class SlowGen3Auth:
        def __init__(self, endpoint, client_credentials, client_scopes):
            # Sleep for 5 seconds to simulate slow network or processing
            time.sleep(10)
            self._access_token = "slow-token"

        def get_access_token(self):
            return self._access_token

    # Replace the real Gen3Auth with our slow fake version
    monkeypatch.setattr("pcdcutils.client.Gen3Auth", SlowGen3Auth)

    # Create a client using valid config
    client = FenceClientManager(
        base_url=FAKE_FENCE_URL,
        client_id=FAKE_CLIENT_ID,
        client_secret=FAKE_CLIENT_SECRET,
    )

    # Call authenticate() — it should fail due to hitting the timeout limit
    # We expect it to raise an exception (e.g., TimeoutError or similar)

    #with pytest.raises(Exception, match="timed out"):
    client.authenticate(raise_exception=True)

    assert not client.is_authenticated() , "here, the is authenticate did eventually authenticate when it should have been killed"

    client.get_auth_token()
    
    assert not client.is_authenticated(), "the call the get_auth_token should have killed before authenticating"

