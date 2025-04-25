#
# pcdcutils.gen3
#
from pcdcutils.errors import Unauthorized
from pcdcutils.signature import SignatureManager
import asyncio

import logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)



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


    def make_gen3_signature(self, payload='', config=None):
        """
        Generate a Gen3 service signature for a standardized payload.
        Accepts a FastAPI/Starlette request object or a string payload (for testing).
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # already in an event loop — schedule the async method and wait for it
            return asyncio.ensure_future(self._make_gen3_signature_async(payload, config))
        else:
            # no event loop — safe to run directly
            # TODO (future improvement): Consider separating the async and sync logic more cleanly.
            # For example, provide a dedicated sync version that internally calls the async one,
            # depending on the context. Or, have all instances the same.
            return asyncio.run(self._make_gen3_signature_async(payload, config))
    

    async def _make_gen3_signature_async(self, payload='', config=None):
        """
        Actual async logic. Use this in FastAPI routes or other async contexts.
        """
        service_name = self.get_gen3_service_header()
        private_key = ''

        # get the signed post data
        if service_name and config:
            private_key = config.get(service_name.upper() + '_PRIVATE_KEY')

        if not private_key:
            raise Unauthorized(f"'{service_name}' is not configured to sign requests.")

        sm = SignatureManager(key=private_key)

        # Legacy/test mode
        if isinstance(payload, str):
            standardized_payload = payload
        else:
            method = payload.method
            body = ''

            # Check url
            try:
                path = payload.url.path
            except AttributeError:
                path = getattr(payload, 'path', '/unknown')
                # If a path url is not provided, let's log it.
                logger.warning("Request object missing .url.path; defaulting to /unknown")

            # Check method
            if method in ['POST', 'PUT', 'PATCH']:
                try:
                    body = (await payload.body()).decode()
                except AttributeError:
                    # If not body and is post, put... then log it.
                    logger.warning("Request object has no .body method for payload")

            # Compile the payload.
            standardized_payload = f"{method} {path}\nGen3-Service: {service_name}"
            if body:
                standardized_payload += f"\n{body}"

        return sm.sign(standardized_payload)


    def valid_gen3_signature(self, payload='', config=None):
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

