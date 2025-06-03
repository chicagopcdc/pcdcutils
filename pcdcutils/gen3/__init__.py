#
# pcdcutils.gen3
#
from pcdcutils.errors import Unauthorized
from pcdcutils.signature import SignatureManager
import asyncio
from urllib.parse import urlparse

import logging

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class SignaturePayload:
    def __init__(self, method, path, headers=None, body=None):
        self.method = method.upper()
        self.path = path
        self.headers = headers or {}
        # TODO make sure body is converted to a string format json.dumps(queryBody, separators=(",", ":"))
        self.body = body or ""

    def get_standardized_payload(self, service_name):
        parsed_url = urlparse(self.path)
        path_only = parsed_url.path
        standardized_payload = f"{self.method} {path_only}\nGen3-Service: {service_name}"
        if self.method in ["POST", "PUT", "PATCH"] and self.body and self.body != "":
            standardized_payload += f"\n{self.body}"
        return standardized_payload


class Gen3RequestManager(object):

    def __init__(self, headers=None):
        self.headers = headers or {}

    def is_gen3_signed(self):
        """
        Returns bool if Signature header is present
        """
        if not self.headers:
            return False
        sig_header = self.headers.get("Signature", None)
        gen3_service_header = self.headers.get("Gen3-Service", None)
        return bool(sig_header) and bool(gen3_service_header)

    def get_gen3_service_header(self):
        """
        Returns the contents of the Gen3-Service header or None
        """
        gen3_service_header = self.headers.get("Gen3-Service", None)
        if gen3_service_header:
            header = gen3_service_header  # .decode('utf-8')
            return header

        return None

    def build_standardized_payload(self, payload):
        """
        Build a standardized payload string for signing or validation.

        This method accepts either a FastAPI Request object (normal usage) or a raw string (for testing or legacy support).
        If a string is passed, it is assumed to already represent the full payload body.

        Args:
            payload (Request | str): Incoming request object or raw body string.

        Returns:
            str: The standardized payload to sign or verify.
        """
        standardized_payload = ""

        if isinstance(payload, str):
            # If payload is already a string (test or legacy mode), return it directly
            logger.debug("build_standardized_payload received a raw string payload.")
            standardized_payload = payload
        elif isinstance(payload, SignaturePayload):
            service_name = self.get_gen3_service_header()
            standardized_payload = payload.get_standardized_payload(service_name)
        else:
            raise ValueError(f"Bad Request: Invalid input type for payload")

        logger.error(standardized_payload)
        payload_encoded = standardized_payload.encode('utf-8')
        return payload_encoded

    def make_gen3_signature(self, payload="", config=None):
        """
        Create a Gen3 service signature for a standardized payload.

        Takes either a FastAPI Request object (normal case) or a raw body string (test case).
        Figures out whether to run async or sync automatically, depending on the environment.

        Args:
            payload (Request | str): The request object or raw body string to sign.
            config (dict, optional): Service config holding the private key.

        Returns:
            str: The hex-encoded signature string.
        """
        # Check for loop running.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            return asyncio.ensure_future(
                self._make_gen3_signature_async(payload, config)
            )
        else:
            return asyncio.run(self._make_gen3_signature_async(payload, config))

    async def _make_gen3_signature_async(self, payload="", config=None):
        """
        Async version of signature generation.

        This handles building the standardized payload and signing it with the private key.
        Used internally — call make_gen3_signature() unless you really need the raw async version.

        Args:
            payload (Request | str): Incoming request or string to sign.
            config (dict, optional): Service config holding the private key.

        Returns:
            str: The hex-encoded signature.

        TODO: PEDS-1416  Once full application is async, we can remove the validator method (make_gen3_signature)
        and just use this method, by removing the internal use on the method name.
        """
        service_name = self.get_gen3_service_header()
        private_key = ""

        if service_name and config:
            private_key = config.get(service_name.upper() + "_PRIVATE_KEY")
            # If we do not have a unique key per service, just use the rsa_private_key.
            # TODO: Future suggestion is to create an unique key per service.
            if not private_key:
                private_key = config.get("RSA_PRIVATE_KEY")

        if not private_key:
            raise Unauthorized(f"'{service_name}' is not configured to sign requests.")

        # key should have been loaded at app_config()
        sm = SignatureManager(key=private_key)

        standardized_payload = self.build_standardized_payload(payload)

        signature = sm.sign(standardized_payload)
        # Sign the standardized_payload.
        logger.info(
            f"Service '{service_name}' signed payload of length {len(standardized_payload)} successfully."
        )
        return signature

    def valid_gen3_signature(self, payload, config=None):
        """
        Verify a Gen3 service request signature.

        Safe to call from both sync and async contexts — this wrapper figures it out.
        Runs the validation by building the standardized payload and checking the signature.

        Allows fallback to returning False temporarily for legacy support.
        (can be removed with PEDS-1415)

        Args:
            payload (Request | str): The request object or raw body string that was signed.
            config (dict, optional): Service config holding the public key for verification.

        Returns:
            bool: True if the signature is valid, otherwise raises Unauthorized.

        TODO: PEDS-1415 Remove fallback behavior after all services are updated
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # already in an event loop — schedule and return a coroutine
            return asyncio.ensure_future(
                self._valid_gen3_signature_async(payload, config)
            )
        else:
            # not in an event loop — run async code directly
            return asyncio.run(self._valid_gen3_signature_async(payload, config))

    async def _valid_gen3_signature_async(self, payload, config=None):
        """
        Async version of Gen3 service signature validation.

        Builds the standardized payload and checks if the provided signature is correct.
        Normally you don't call this directly — use valid_gen3_signature() instead.

        Raises Unauthorized on failure, or returns False if fallback is enabled.
        (can be removed with PEDS-1415)

        Args:
            payload (payload | str): Incoming payload or raw body string.
            config (dict, optional): Service config holding the public key.

        Returns:
            bool: True if the signature is valid, otherwise raises Unauthorized.

        TODO: PEDS-1416 Once full application is async, we can remove the validator method (valid_gen3_signature)
        and just use this method, by removing the internal use on the method name.
        """
        service_name = self.get_gen3_service_header()
        public_key = ""

        if service_name and config:
            public_key = getattr(config, service_name.upper() + "_PUBLIC_KEY", None)
            # If we do not have a unique key per service, just use the rsa_public_key.
            # TODO: Future suggestion is to create an unique key per service.
            if not public_key:
                public_key = getattr(config, "RSA_PUBLIC_KEY", None)

        if not public_key:
            raise Unauthorized(
                f"'{service_name}' is not configured to send payloads to this service"
            )

        # key should have been loaded at app_config()
        sm = SignatureManager(key=public_key)

        # Build the standardized payload
        standardized_payload = self.build_standardized_payload(payload)

        # This assumes self.headers is populated correctly
        try:
            if not sm.verify_signature(
                payload=standardized_payload, headers=self.headers
            ):
                raise Unauthorized("Signature verification failed.")
        except Unauthorized:
            if getattr(
                self, "_allow_legacy_false_fallback", True
            ):  # <-- fallback on by default
                logger.warning(
                    "Signature verification failed; returning False for legacy fallback. TODO: Remove fallback."
                )
                return False
            else:
                raise

        # Verified the standardized_payload.
        logger.info(
            f"[Gen3 Signature] Service '{service_name}' signature verified successfully."
        )
        return True
