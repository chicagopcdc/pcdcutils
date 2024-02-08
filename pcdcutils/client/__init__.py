import requests
import base64
import urllib.parse


class FenceClientManager(object):

    def __init__(self, fence_url=None, client_id=None, client_secret=None):
        self.fence_url = fence_url
        self.client_id = client_id
        self.client_secret = client_secret


    def is_valid(self):
        if not self.fence_url or not self.client_id or not self.client_secret:
            return False

        # TODO ping the fence base URL to make use it is correct and reacheable

        return True



    def get_auth_token(self):
        '''
        Returns bool if Signature header is present
        '''
        if self.is_valid():
            url = self.fence_url + "/oauth2/token?grant_type=client_credentials"
            scopes = "openid user"
            #url encode the value
            payload = "scope=" + urllib.parse.quote(scopes)

            auth_str = client_id + ":" + client_secret
            #base64 encode the credentials
            auth_str_bytes = auth_str.encode("ascii") 
            auth_base64_bytes = base64.b64encode(auth_str_bytes) 
            auth_base64_string = auth_base64_bytes.decode("ascii") 

            headers = {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Authorization': 'Basic ' + auth_base64_string,
            }

            response = requests.request("POST", url, headers=headers, data=payload)
            if response.status_code == 200:
                json_response = response.json()
                return json_response["access_token"]
            else:
                print("ERROR!")
                print(response.text)

        return None

