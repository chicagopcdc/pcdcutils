from Crypto.PublicKey import RSA 
from Crypto.Signature import pkcs1_15 
from Crypto.Hash import SHA256 
from types import SimpleNamespace
import pytest
from pcdcutils.gen3 import Gen3RequestManager
import os

# openssl genpkey -algorithm RSA -out PRIVATE_NAME.pem -pkeyopt rsa_keygen_bits:2048
# openssl rsa -pubout -in PRIVATE_NAME.pem -out PUB_NAME.pem
# To run the tests, create a keys directory in the tests folder and create key pairs private/public_key1 and 2.pem


def test_successful_make_sig():
  body = 'aaaaa'
  pri_key_path = os.getcwd() + '/tests/keys/private_key1.pem'
  keyfile = open(pri_key_path, "r").read()
  pri_key = RSA.import_key(keyfile)
  g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "service"})
  sig = g3.make_gen3_signature(body, {"SERVICE_PRIVATE_KEY": pri_key})
  assert sig == "4abceb628848385d3d8f03c1530bbd3d72cb194a6fe6ea20a54a7d2004a4dce16bfe9e46e0a73ddf7388482550ff135ff039bcb0cebc8fc5a095e2021c20cc0f7bfc5d80ab77cb4ad9f4603857e2781eb0d55279a9198a5048814c5cbd5e7fdc75f9722754bf11b87a9fa9703008fa3757bdeac644a46331a51d2b88d410bcf0"


def test_bad_make_sig():
  body = 'aaaaa'
  bad_key_path = os.getcwd() + '/tests/keys/public_key1.pem'
  keyfile = open(bad_key_path, "r").read()
  bad_key = RSA.import_key(keyfile)
  g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "service"})
  with pytest.raises(TypeError) as ex:
    sig = g3.make_gen3_signature(body, {"SERVICE_PRIVATE_KEY": bad_key})
  assert "This is not a private key" in str(ex.value)


def test_successful_validate_sig():
  body = 'aaaaa'
  pri_key_path = os.getcwd() + '/tests/keys/private_key1.pem'
  keyfile = open(pri_key_path, "r").read()
  pri_key = RSA.import_key(keyfile)
  g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "service"})
  sig = g3.make_gen3_signature(body, {"SERVICE_PRIVATE_KEY": pri_key})
  signed_g3 = Gen3RequestManager({"Signature": "signature " + sig, "Gen3-Service": "service"})
  pub_key_path = os.getcwd() + '/tests/keys/public_key1.pem'
  keyfile = open(pub_key_path, "r").read()
  pub_key = RSA.import_key(keyfile)
  assert signed_g3.valid_gen3_signature(body, {"SERVICE_PUBLIC_KEY": pub_key})


def test_bad_validate_sig():
  #Use wrong public key for the private key
  body = 'aaaaa'
  pri_key_path = os.getcwd() + '/tests/keys/private_key2.pem'
  keyfile = open(pri_key_path, "r").read()
  pri_key = RSA.import_key(keyfile)
  g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "service"})
  sig = g3.make_gen3_signature(body, {"SERVICE_PRIVATE_KEY": pri_key})
  signed_g3 = Gen3RequestManager({"Signature": "signature " + sig, "Gen3-Service": "service"})
  pub_key_path = os.getcwd() + '/tests/keys/public_key1.pem'
  keyfile = open(pub_key_path, "r").read()
  pub_key = RSA.import_key(keyfile)
  assert signed_g3.valid_gen3_signature(body, {"SERVICE_PUBLIC_KEY": pub_key}) == False


def test_make_gen3_signature_with_request_object():
    # Simulated production request
    fake_request = SimpleNamespace(
        method='POST',
        path='/admin/users/selected',
        get_data=lambda as_text=True: '{"usernames": ["someone"]}'
    )

    # Generate a key
    key = RSA.generate(2048)

    headers = {
        "Signature": None,
        "Gen3-Service": "test-service"
    }

    g3 = Gen3RequestManager(headers)
    config = {
        "TEST-SERVICE_PRIVATE_KEY": key
    }

    signature = g3.make_gen3_signature(fake_request, config)

    assert isinstance(signature, str)
    assert len(signature) > 10  # sanity check

def test_signature_logs(caplog):
    # Simulate a Flask-like request object
    fake_request = SimpleNamespace(
        method='POST',
        path='/admin/users/selected',
        get_data=lambda as_text=True: '{"usernames": ["someone"]}'
    )

    # Generate a temporary private key for the test
    test_key = RSA.generate(2048)

    # Create the Gen3RequestManager instance
    g3 = Gen3RequestManager({"Signature": None, "Gen3-Service": "test-service"})

    # Provide a config dict with the test private key
    config = {
        "TEST-SERVICE_PRIVATE_KEY": test_key
    }