# import requests
# import base64
# import urllib.parse

from gen3.auth import Gen3Auth, Gen3AuthError


### USAGE
# client_credential = FenceClientManager(
#         fence_url=config.PCDC_COMMON_BASENAME, 
#         client_id={FENCE_CLIENT_ID}, 
#         client_secret={FENCE_CLIENT_SECRET})
# client_credential.authenticate()
# client_credential.get_auth_token()

class FenceClientManager(object):

    def __init__(self, base_url=None, client_id=None, client_secret=None):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret

        self.scopes = "openid user" #"user data openid"
        self.auth = None


    def is_valid(self):
        if not self.base_url or not self.client_id or not self.client_secret:
            return False

        # TODO ping the fence base URL to make use it is correct and reacheable

        return True

    def is_authenticated(self):
        return True if self.auth else False


    def authenticate(self):
        if self.is_valid():
            try:
                self.auth = Gen3Auth(
                    endpoint=self.base_url,
                    client_credentials=(self.client_id, self.client_secret),
                    client_scopes = self.scopes
                )
            except Gen3AuthError as err:
                print(err)
                print(f"AUTH ERROR: {err.error}")

            



    def get_auth_token(self):
        if self.auth is None:
            return ""
        return self.auth.get_access_token()
        # url = self.base_url + "user/oauth2/token?grant_type=client_credentials"
        # 
        # #url encode the value
        # payload = "scope=" + urllib.parse.quote(self.scopes)

        # auth_str = client_id + ":" + client_secret
        # #base64 encode the credentials
        # auth_str_bytes = auth_str.encode("ascii") 
        # auth_base64_bytes = base64.b64encode(auth_str_bytes) 
        # auth_base64_string = auth_base64_bytes.decode("ascii") 

        # headers = {
        #   'Content-Type': 'application/x-www-form-urlencoded',
        #   'Authorization': 'Basic ' + auth_base64_string,
        # }

        # response = requests.request("POST", url, headers=headers, data=payload)
        # if response.status_code == 200:
        #     json_response = response.json()
        #     return json_response["access_token"]
        # else:
        #     print("ERROR!")
        #     print(response.text)
        # return None

