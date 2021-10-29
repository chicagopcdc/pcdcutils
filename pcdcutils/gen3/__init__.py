#
# pcdcutils.gen3
#
from os import environ
from pcdcutils.errors import Unauthorized
from pcdcutils.signature import SignatureManager


class Gen3RequestManager(object):

    def __init__(self, headers):
        if headers and isinstance(headers, dict):
            self.headers = headers


    def is_gen3_signed(self):
        '''
        Returns bool if Signature header is present
        '''
        if not self.headers:
            return False
        sig_header = self.headers.get("Signature", False)
        gen3_service_header = self.headers.get("Gen3-Service", False)
        return (bool(sig_header) and bool(gen3_service_header))


    def get_gen3_service_header(self):
        '''
        Returns the contents of the Gen3-Service header or None
        '''
        header_utf8 = self.headers.get("Gen3-Service", '')
        if header_utf8:
            header = header_utf8.decode('utf-8')
            return header

        return None


    def set_auth_gen3_services(self, auth_gen3_services=[]):
        
        if auth_gen3_services:
            for i, service in enumerate(auth_gen3_services):
                auth_gen3_services[i] = service.upper()

            self.auth_gen3_services = auth_gen3_services
            

    # fence passes in data payload from request 
    def valid_gen3_signature(self, payload):
        '''
        Validates an authorized Gen3 service request against auth_gen3_services
        Validates a signature header for a signed request
        returns bool if valid or not
        '''
        public_key_path = ''
        service_name = self.get_gen3_service_header()
        # get the signed post data

        if service_name.upper() in self.auth_gen3_services:
            public_key_path = environ.get(service_name.upper() + '_PUBLIC_KEY')
        else:
            raise Unauthorized(f"'{service_name}' is not an authorized Gen3 service")
        
        signature_mgr = SignatureManager(key_path=public_key_path)

        return  signature_mgr.verify_signature(payload=payload)