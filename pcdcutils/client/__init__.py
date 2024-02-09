# import requests
# import base64
# import urllib.parse

from gen3.auth import Gen3Auth


class FenceClientManager(object):

    def __init__(self, base_url=None, client_id=None, client_secret=None):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret

        self.scopes = "openid user" #"user data openid"
        self.auth = None


    def is_valid(self):
        if not self.fence_url or not self.client_id or not self.client_secret:
            return False

        # TODO ping the fence base URL to make use it is correct and reacheable

        return True

    def authenticate(self):
        if self.is_valid():
            self.auth = Gen3Auth(
                endpoint="https://portal-dev.pedscommons.org",
                client_credentials=(self.client_id, self.client_secret),
                client_scopes = self.scopes
            )


    def get_auth_token(self):
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
