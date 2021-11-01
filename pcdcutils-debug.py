# 
# pcdcutils handy test script
# for easy testing with pcdcutils
# by: dvenckus@uchicago.edu

# import requests
import json
import os
from pcdcutils.signature import SignatureManager
from pcdcutils.gen3 import Gen3RequestManager
from pcdcutils.environment import is_env_enabled

#--------------------------------------
# private_key_path = '<insert private key path>'
# public_key_path = '<insert private key path>'
# user_firstname = '<insert test firstname>'
# user_lastname = '<insert test lastname>'
# consortium_code = '<insert consortium_code>'
#--------------------------------------

# ----- Populate these fields !!! -----
private_key_path = '<path to>/amanuensis-jwt-keys/jwt_private_key.pem'
public_key_path = '<path to>/amanuensis-jwt-keys/jwt_public_key.pem'
#--------------------------------------


def get_jwt():
  # mock jwt - similar to real code base request setup
  return private_key_path
 
def get_message():
  usernames = [
    "lgraglia@uchicago.edu",
    "dvenckus@uchicago.edu"
  ]
  queryBody = {
    "usernames": usernames
  }
  # queryBody = "My dog has fleas"
  body = json.dumps(queryBody)
  return body  #.encode('utf-8')


# Mock app.config
config = {
  'AMANUENSIS_PUBLIC_KEY_PATH': public_key_path
}

# ------ pcdcutils.signature ------
# sign the message payload
message = get_message()
signature = SignatureManager(key_path=private_key_path).sign(message)

# url = 'http://localhost/user/admin/users/selected'  
headers = {'Content-Type': 'application/json'}
jwt = get_jwt()
headers['Authorization'] = 'bearer ' + jwt
headers['Signature'] = b'signature ' + signature
headers['Gen3-Service'] = b'amanuensis'

# We are not really going to do this here
# r = requests.post(url=url, headers=headers, data=message)
# print("output: ")
# print(r)

# Pre-load the public key
# load amanuensis public key for cross-service access
key_path = config.get("AMANUENSIS_PUBLIC_KEY_PATH", None)
config["AMANUENSIS_PUBLIC_KEY"] =  SignatureManager(key_path=key_path).get_key()

# ------ pcdcutils.gen3 ------
# validate the message payload
gen3_service_mgr = Gen3RequestManager(headers=headers)
rtn = gen3_service_mgr.is_gen3_signed()
print(f"Is Gen3 Signed: " + ("True" if rtn else "False"))

rtn = gen3_service_mgr.valid_gen3_signature(message, config)
print(f"Is Gen3 Signature Valid: " + ("True" if rtn else "False"))

# ------ pcdcutils.environment ------
os.environ['GEN3_DEBUG'] = "1"

if is_env_enabled('GEN3_DEBUG'):
  print("GEN3_DEBUG is enabled")
else:
  print("GEN3_DEBUG is disabled")