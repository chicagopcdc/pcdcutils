import errno
import os
import signal
import functools
import json
import requests

from gen3.auth import Gen3Auth, Gen3AuthError


class TimeoutError(Exception):
    pass


def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wrapper

    return decorator


### USAGE
# client_credential = FenceClientManager(
#         fence_url={PCDC_COMMON_BASENAME}, 
#         client_id={FENCE_CLIENT_ID}, 
#         client_secret={FENCE_CLIENT_SECRET})
# client_credential.authenticate()
# client_credential.get_auth_token()
class FenceClientManager(object):

    def __init__(self, base_url=None, client_id=None, client_secret=None, timeout=2):
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


    # @timeout(30, os.strerror(errno.ETIMEDOUT))
    @timeout(2)
    def authenticate(self):
        if self.is_valid():
            try:
                self.auth = Gen3Auth(
                    endpoint=self.base_url,
                    client_credentials=(self.client_id, self.client_secret),
                    client_scopes = self.scopes
                )
            except TimeoutError:
                # TODO send notification to 
                print(f"TIMEOUT: Connection with client_credential to {self.base_url}/user failed.")
            except Gen3AuthError as err:
                print(f"AUTH ERROR: {err}")


    def get_auth_token(self):
        if not self.is_authenticated:
            self.authenticate()

        if self.is_authenticated():
            return self.auth.get_access_token()

        return ""

    def get_gen3_auth_instance(self):
        return self.auth



class GuppyManager(object):

    def __init__(self, base_url=None, timeout=5, access_token=None):
        self.base_url = base_url
        # TODO check base_url is valid
        self.graphql_endpoint = self.base_url + "/guppy/graphql/"
        self.download_endpoint = self.base_url + "/guppy/download/"
        self.data_version_endpoint = self.base_url + "/guppy/_data_version"

        self.access_token = access_token
        self.timeout = timeout


    def graphql_query(query_string, variables):
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

            print("LUCAAAAAAAA")
            print(response.headers)

            response.raise_for_status()
        except requests.exceptions.Timeout: #except requests.Timeout:
            # Maybe set up for a retry, or continue in a retry loop
            # TODO send notification to 
            print(f"TIMEOUT: Connection with client_credential to {self.graphql_endpoint} failed.")
            return {}
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




    def download_query(type, fields, filters, sort, accessibility="accessible"):
        # query_string = "{ my_index { my_field } }"
        queryBody = { "type": type }
        if fields:
            if "honest_broker_subject_id" not in fields:
                fields.append("honest_broker_subject_id")
            queryBody["fields"] = fields
        if filters:
            queryBody["filter"] = filters["filter"] # getGQLFilter(filter);
        if sort:
            queryBody["sort"] = sort 
        if accessibility:
            queryBody["accessibility"] = accessibility
        # body = json.dumps(queryBody, separators=(',', ':'))
        body = queryBody

        # headers = {'Content-Type': 'application/json'}
        headers = {}
        headers['Authorization'] = 'bearer ' + self.access_token


        response = requests.post(
            self.download_endpoint,
            json=body,
            headers=headers,
            timeout=self.timeout
        )

        print("LUCAAAAAAAA")
        print(response.headers)
        
        try:
            response.raise_for_status()
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
















