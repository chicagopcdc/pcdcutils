#
# pcdcutils.gen3
#
from pcdcutils.errors import Unauthorized
from pcdcutils.signature import SignatureManager


class Gen3RequestManager(object):

    def __init__(self, headers=None):
        if headers:
            self.headers = headers


    def is_gen3_signed(self):
        '''
        Returns bool if Signature header is present
        '''
        if not self.headers:
            return False
        sig_header = self.headers.get("Signature", None)
        gen3_service_header = self.headers.get("Gen3-Service", None)
        return (bool(sig_header) and bool(gen3_service_header))


    def get_gen3_service_header(self):
        '''
        Returns the contents of the Gen3-Service header or None
        '''
        header_utf8 = self.headers.get("Gen3-Service", '')
        if header_utf8:
            header = header_utf8 # .decode('utf-8')
            return header

        return None
            

    def valid_gen3_signature(self, payload=None, config=None):
        '''
        Validates an authorized Gen3 service request against auth_gen3_services
        Validates a signature header for a signed request
        returns bool if valid or not
        '''
        public_key = ''
        service_name = self.get_gen3_service_header()
        # get the signed post data

        if service_name and config:
            public_key = config.get(service_name.upper() + '_PUBLIC_KEY', None)

        if not public_key:
            raise Unauthorized(f"'{service_name}' is not configured to send requests to this service")
        
        # key should have been loaded at app_config()
        sm = SignatureManager(key=public_key)

        return sm.verify_signature(payload=payload, headers=self.headers)