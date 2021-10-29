#
# pcdcutils.signature
#

import os
import binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from pcdcutils.errors import NoKeyError, KeyPathInvalidError, Unauthorized



# amanuensis passes os.environ.get("PRIVATE_KEY_PATH", None) as private_key_path

class SignatureManager(object):

    # key = None
    # key_path = None
    # signature = None

    def __init__(self, key_path=None, key=None):
        if key:
            self.key = key

        if key_path:
            self.key_path = key_path

        self.load_key()


    def load_key(self):
        '''
        load key from key_path
        '''
        if self.key:
            # key already loaded
            return self.key

        elif self.key_path:
            # load the key from the path
            if not os.path.exists(self.key_path):
                raise KeyPathInvalidError("key_path is not found or invalid")

            try:
                keyfile = open(self.key_path, "r").read()
                self.key = RSA.import_key(keyfile)
                
                if self.key is None:
                    raise NoKeyError(f"private key not loaded, '{self.key_path}'")
            except OSError:
                raise KeyPathInvalidError(f"could not read key_path, '{self.key_path}'") from None

        else:
            raise KeyPathInvalidError("key and key_path are empty")

        return self.key


    def get_key(self):
        return self.key


    def sign(self, payload=''):
        '''
        Create signature for payload
        '''
        if self.key is None:
            raise NoKeyError("key not loaded")

        hash = SHA256.new(payload.encode('utf-8'))
        self.signature = pkcs1_15.new(self.key).sign(hash)
        hexed_signature = binascii.hexlify(self.signature)
        return hexed_signature


    def is_signed(self, headers):
        '''
        checks the headers for a Signature
        returns bool, Signature header exists or not
        '''
        header = None
        if isinstance(headers, dict):
            header = headers.get("Signature", '')
        return bool(header)


    def get_signature(self, headers):
        '''
        Accepts the request headers and retrieves the signature
        Raises:
            - Unauthorized, if header is missing or not in the correct format
        '''
        if not isinstance(headers, dict):
            raise Unauthorized("missing header")

        header = headers.get("Signature", None)
        if not header:
            raise Unauthorized("missing signature header")

        try:
            signature_string = header.decode('utf-8')
            prefix, hexed_signature = signature_string.split(" ")
            self.signature = binascii.unhexlify(hexed_signature)
        except ValueError:
            raise Unauthorized("signature header not in expected format") from None

        if prefix.lower() != "signature":
            raise Unauthorized("expected signature token in auth header")

        return self.signature


    def verify_signature(self, payload=None, headers=None):
        """
        Check if the signature header is valid
        """
        if not self.signature:
            self.get_signature(headers)

        if not self.key or not self.signature or not payload:
            raise Unauthorized("verify_signature missing key, signature, or payload")
        try:
            hash = SHA256.new(payload)
            pkcs1_15.new(self.key).verify(hash, self.signature)
            return True
        except ValueError as e:
            return False
        
    