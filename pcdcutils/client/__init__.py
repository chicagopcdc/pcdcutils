import errno
import os
import functools
import json
import requests
import time

from gen3.auth import Gen3Auth, Gen3AuthError
from multiprocessing import Process, Queue
import threading
import asyncio

class TimeoutError(Exception):
    pass

class FakeGen3Auth:
    def __init__(self, endpoint, client_credentials, client_scopes, success=False):
        # Save the inputs so we can check them if needed
        self.endpoint = endpoint
        self.client_credentials = client_credentials
        self.client_scopes = client_scopes
        # We set a fake access token value
        self._access_token = "fake-token"

    def get_access_token(self):
        # This returns the fake token instead of making a real API call
        return self._access_token


def run_authenticate_with_timeout(base_url, client_id, client_secret, scopes, seconds=10):
    q = Queue()
    print("HERE")
    p = Process(target=_auth_worker, args=(base_url, client_id, client_secret, scopes, q))
    print("HERE1")
    p.start()
    print("HERE2")
    p.join(seconds)
    print("HERE3")

    if p.is_alive():
        p.terminate()
        p.join()
        print("who")
        raise TimeoutError(f"Authentication timed out after {seconds} seconds")
    print("HERE4")
    if not q.empty():
        print("who1")
        status, payload = q.get()
        if status == "error":
            print("hi")
            raise payload
        return payload
    else:
        print("who2")
        raise TimeoutError("No result returned from authentication process")

def _auth_worker(base_url, client_id, client_secret, scopes, q):
    try:
        #change to FakeGen3Auth for testing test_fence_client_manager_timeout && success
        auth = Gen3Auth(
            endpoint=base_url,
            client_credentials=(client_id, client_secret),
            client_scopes=scopes,
        )
        #add time.sleep(10) for test_fence_client_manager_timeout
        #time.sleep(10)

        q.put(("result", auth))
    except Exception as e:
        q.put(("error", e))



### USAGE
# client_credential = FenceClientManager(
#         fence_url={PCDC_COMMON_BASENAME}, 
#         client_id={FENCE_CLIENT_ID}, 
#         client_secret={FENCE_CLIENT_SECRET})
# client_credential.authenticate()
# client_credential.get_auth_token()
class FenceClientManager(object):

    def __init__(self, base_url=None, client_id=None, client_secret=None, timeout=5):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout

        self.scopes = "openid user" #"user data openid"
        self.auth = None

    def is_valid(self):
        if not self.base_url or not self.client_id or not self.client_secret:
            return False

        # TODO ping the fence base URL to make use it is correct and reacheable

        return True

    def is_authenticated(self):
        return True if self.auth else False

    def authenticate(self, raise_exception=False):
        print("INAUTHENTICATE")
        if self.is_valid():
            try:
                self.auth = run_authenticate_with_timeout(
                    self.base_url,
                    self.client_id,
                    self.client_secret,
                    self.scopes,
                    seconds=self.timeout
                )
                print("my_auth:", self.auth)
            except TimeoutError:
                print(f"TIMEOUT: Connection with client_credential to {self.base_url}/user failed.")
            except Gen3AuthError as err:
                print(f"AUTH ERROR: {err}")
                # Optionally log or handle silently

    def get_auth_token(self):
        print("INGETAUTHTOKEN")
        if not self.is_authenticated():
            self.authenticate(raise_exception=True)

        if self.is_authenticated():
            return self.auth.get_access_token()

        return ""

    def get_gen3_auth_instance(self):
        return self.auth

class GuppyManager(object):

    def __init__(self, base_url=None, timeout=10, access_token=None):
        self.base_url = base_url
        # TODO check base_url is valid
        self.graphql_endpoint = self.base_url + "/guppy/graphql/"
        self.download_endpoint = self.base_url + "/guppy/download/"
        self.data_version_endpoint = self.base_url + "/guppy/_data_version"

        self.access_token = access_token
        self.timeout = timeout


    #TODO bring the logic to build the filter / variables here.
    def graphql_query(self, query_string, variables):
        # query_string example "query ($filter: JSON){\n  _aggregation{\n    subject(filter: $filter, accessibility: all){\n      _totalCount\n    }\n  }\n}"

        headers = {}
        if self.access_token:
            headers['Authorization'] = 'bearer ' + self.access_token

        try:
            response = requests.post(
                self.graphql_endpoint,
                json={"query": query_string, "variables": variables},
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
        except requests.exceptions.Timeout: #except requests.Timeout:
            # Maybe set up for a retry, or continue in a retry loop
            # TODO send notification to 
            print(f"TIMEOUT: Connection with client_credential to {self.graphql_endpoint} failed.")
            #TODO raise connection error instead and return the info
            raise TimeoutError()
        except requests.HTTPError as exception:
            print(
                "Error: status code {}; details:\n{}".format(
                    response.status_code, response.text
                )
            )
            raise

        try:
            return response.json()
        except Exception:
            print(f"Did not receive JSON: {response.text}")
            raise


    def download_query(self, type, fields, filters, sort, accessibility="accessible"):
        # query_string = "{ my_index { my_field } }"
        queryBody = { "type": type }
        if fields:
            queryBody["fields"] = fields
        if filters:
            queryBody["filter"] = filters # getGQLFilter(filter);
        if sort:
            queryBody["sort"] = sort 
        if accessibility:
            queryBody["accessibility"] = accessibility
        # body = json.dumps(queryBody, separators=(',', ':'))
        body = queryBody

        # headers = {'Content-Type': 'application/json'}
        headers = {}
        if self.access_token:
            headers['Authorization'] = 'bearer ' + self.access_token

        try:
            response = requests.post(
                self.download_endpoint,
                json=body,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
        except requests.exceptions.Timeout: #except requests.Timeout:
            # Maybe set up for a retry, or continue in a retry loop
            # TODO send notification to 
            print(f"TIMEOUT: Connection with client_credential to {self.download_endpoint} failed.")
            #TODO raise connection error instead and return the info
            raise TimeoutError()
        except requests.HTTPError as exception:
            print(
                "Error: status code {}; details:\n{}".format(
                    response.status_code, response.text
                )
            )
            raise

        try:
            return response.json()
        except Exception:
            print(f"Did not receive JSON: {response.text}")
            raise


    def data_version(self):
        headers = {}
        if self.access_token:
            headers['Authorization'] = 'bearer ' + self.access_token

        try:
            response = requests.get(
                self.data_version_endpoint,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
        except requests.exceptions.Timeout: #except requests.Timeout:
            # Maybe set up for a retry, or continue in a retry loop
            # TODO send notification to 
            print(f"TIMEOUT: Connection with client_credential to {self.data_version_endpoint} failed.")
            #TODO raise connection error instead and return the info
            raise TimeoutError()
        except requests.HTTPError as exception:
            print(
                "Error: status code {}; details:\n{}".format(
                    response.status_code, response.text
                )
            )
            raise

        try:
            # return response.json()
            return response.text
        except Exception:
            print(f"Did not receive JSON: {response.text}")
            raise















