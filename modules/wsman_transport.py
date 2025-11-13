#!/usr/bin/env python3
"""
Custom WSMan transport layer
"""

import logging
import typing
import uuid
import xml.etree.ElementTree as ET

import requests
import requests.adapters
from pypsrp._utils import get_hostname
from pypsrp.encryption import WinRMEncryption
from pypsrp.exceptions import WinRMTransportError
from pypsrp.wsman import (
    AUTH_KWARGS,
    NAMESPACES,
    SUPPORTED_AUTHS,
    WSMan,
    _TransportHTTP,
)
from urllib3.util.retry import Retry

try:
    from requests_credssp import HttpCredSSPAuth
except ImportError as err:
    _requests_credssp_import_error = (
        "Cannot use CredSSP auth as requests-credssp is not installed: %s" % err
    )

    class HttpCredSSPAuth(object):
        def __init__(self, *args, **kwargs):
            raise ImportError(_requests_credssp_import_error)


logger = logging.getLogger(__name__)

class WSManDeploy(WSMan):
    """
    Enhanced WSMan class for Deploy with improved error handling and session management.
    Based on evil-winrm-py's implementation.
    """

    def __init__(
        self,
        server: str,
        max_envelope_size: int = 153600,
        operation_timeout: int = 20,
        port: typing.Optional[int] = None,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        ssl: bool = True,
        path: str = "wsman",
        auth: str = "negotiate",
        cert_validation: bool = True,
        connection_timeout: int = 30,
        encryption: str = "auto",
        proxy: typing.Optional[str] = None,
        no_proxy: bool = False,
        locale: str = "en-US",
        data_locale: typing.Optional[str] = None,
        read_timeout: int = 30,
        reconnection_retries: int = 3,
        reconnection_backoff: float = 2.0,
        user_agent: str = "Microsoft WinRM Client",
        **kwargs: typing.Any,
    ) -> None:
        """
        Initialize WSMan transport with Deploy-specific improvements.

        Args:
            server: The hostname or IP address of the host to connect to
            max_envelope_size: The maximum size of the envelope that can be sent
            operation_timeout: Time to wait for response or fault
            port: The port to connect to (default: 5986 if ssl=True, else 5985)
            username: The username to connect with
            password: The password for the above username
            ssl: Whether to connect over http or https
            path: The WinRM path to connect to
            auth: The auth protocol (basic, certificate, negotiate, credssp, ntlm, kerberos)
            cert_validation: Whether to validate the server's SSL cert
            connection_timeout: The timeout for connecting to the HTTP endpoint
            read_timeout: The timeout for receiving from the HTTP endpoint
            encryption: Controls encryption setting (auto, always, never)
            proxy: The proxy URL used to connect to the remote host
            no_proxy: Whether to ignore environment proxy vars
            locale: The language for response text (default: en-US)
            data_locale: The format for numerical data in responses
            reconnection_retries: Number of retries on connection problems
            reconnection_backoff: Backoff factor for retries
            user_agent: The user agent for HTTP requests
            **kwargs: Additional auth-specific parameters
        """
        logger.debug(
            "Initialising WSManDeploy with envelope size %d and timeout %d",
            max_envelope_size,
            operation_timeout,
        )
        self.session_id = str(uuid.uuid4())
        self.locale = locale
        self.data_locale = self.locale if data_locale is None else data_locale
        self.transport = _TransportHTTPDeploy(
            server,
            port,
            username,
            password,
            ssl,
            path,
            auth,
            cert_validation,
            connection_timeout,
            encryption,
            proxy,
            no_proxy,
            read_timeout,
            reconnection_retries,
            reconnection_backoff,
            user_agent,
            **kwargs,
        )
        self.max_envelope_size = max_envelope_size
        self.operation_timeout = operation_timeout

        # Register well known namespace prefixes
        for key, value in NAMESPACES.items():
            ET.register_namespace(key, value)

        # Calculate max payload size based on envelope size
        self.max_payload_size = self._calc_envelope_size(max_envelope_size)


class _TransportHTTPDeploy(_TransportHTTP):
    """
    HTTP transport for Deploy with improved session management,
    retry logic, and error handling.
    """

    def __init__(
        self,
        server: str,
        port: typing.Optional[int] = None,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        ssl: bool = True,
        path: str = "wsman",
        auth: str = "negotiate",
        cert_validation: bool = True,
        connection_timeout: int = 30,
        encryption: str = "auto",
        proxy: typing.Optional[str] = None,
        no_proxy: bool = False,
        read_timeout: int = 30,
        reconnection_retries: int = 3,
        reconnection_backoff: float = 2.0,
        user_agent: str = "Microsoft WinRM Client",
        **kwargs: typing.Any,
    ) -> None:
        """Initialize enhanced HTTP transport."""
        self.server = server
        self.port = port if port is not None else (5986 if ssl else 5985)
        self.username = username
        self.password = password
        self.ssl = ssl
        self.path = path

        if auth not in SUPPORTED_AUTHS:
            raise ValueError(
                "The specified auth '%s' is not supported, "
                "please select one of '%s'" % (auth, ", ".join(SUPPORTED_AUTHS))
            )
        self.auth = auth
        self.cert_validation = cert_validation
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.reconnection_retries = reconnection_retries
        self.reconnection_backoff = reconnection_backoff
        self.user_agent = user_agent

        # Determine message encryption logic
        if encryption not in ["auto", "always", "never"]:
            raise ValueError(
                "The encryption value '%s' must be auto, always, or never" % encryption
            )
        enc_providers = ["credssp", "kerberos", "negotiate", "ntlm"]
        if ssl:
            # Messages are automatically encrypted with TLS
            self.wrap_required = encryption == "always"
            if self.wrap_required and self.auth not in enc_providers:
                raise ValueError(
                    "Cannot use message encryption with auth '%s', either set "
                    "encryption='auto' or use one of the following auth "
                    "providers: %s" % (self.auth, ", ".join(enc_providers))
                )
        else:
            # Messages should be encrypted when not using SSL
            self.wrap_required = not encryption == "never"
            if self.wrap_required and self.auth not in enc_providers:
                raise ValueError(
                    "Cannot use message encryption with auth '%s', either set "
                    "encryption='never', use ssl=True or use one of the "
                    "following auth providers: %s"
                    % (self.auth, ", ".join(enc_providers))
                )
        self.encryption: typing.Optional[WinRMEncryption] = None

        self.proxy = proxy
        self.no_proxy = no_proxy

        # Initialize auth-specific parameters
        self.certificate_key_pem: typing.Optional[str] = None
        self.certificate_pem: typing.Optional[str] = None
        for kwarg_list in AUTH_KWARGS.values():
            for kwarg in kwarg_list:
                setattr(self, kwarg, kwargs.get(kwarg, None))

        self.endpoint = self._create_endpoint(self.ssl, self.server, self.port, self.path)
        logger.debug(
            "Initialising HTTP transport for endpoint: %s, user: %s, auth: %s",
            self.endpoint,
            self.username,
            self.auth,
        )
        self.session: typing.Optional[requests.Session] = None

    def send(self, message: bytes) -> bytes:
        """
        Send a message to the remote host with automatic session reset on errors.

        Args:
            message: The message to send

        Returns:
            The response from the server

        Raises:
            WinRMTransportError: If the request fails
        """
        hostname: str = get_hostname(self.endpoint)
        if self.session is None:
            self.session = self._build_session()

            # Send initial blank message to setup security context for encryption
            if self.wrap_required:
                request = requests.Request("POST", self.endpoint, data=None)
                prep_request = self.session.prepare_request(request)
                self._send_request(prep_request)

                # Determine encryption protocol
                protocol: typing.Union[str, None] = WinRMEncryption.SPNEGO
                
                # Type guard: Check if auth object has contexts attribute
                if isinstance(self.session.auth, HttpCredSSPAuth):
                    protocol = WinRMEncryption.CREDSSP
                elif (
                    hasattr(self.session.auth, 'contexts') and
                    self.session.auth is not None and
                    hasattr(self.session.auth, 'contexts')
                ):
                    # Type guard: Safely access contexts dictionary
                    auth_contexts = getattr(self.session.auth, 'contexts', {})
                    if (
                        isinstance(auth_contexts, dict) and
                        hostname in auth_contexts and
                        hasattr(auth_contexts[hostname], 'response_auth_header') and
                        auth_contexts[hostname].response_auth_header == "kerberos"
                    ):
                        protocol = WinRMEncryption.KERBEROS
                    
                    # Create encryption with safe context access
                    if hostname in auth_contexts and protocol is not None:
                        self.encryption = WinRMEncryption(
                            auth_contexts[hostname],
                            protocol
                        )

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Sending message: %s", message.decode("utf-8"))

        # Type guard: Safe headers copy
        headers: typing.Dict[str, typing.Union[str, bytes]] = {}
        if self.session is not None and hasattr(self.session.headers, 'copy'):
            # Convert MutableMapping to dict safely
            headers = {k: v for k, v in self.session.headers.items()}
        elif self.session is not None:
            headers = {k: v for k, v in self.session.headers.items()}
            
        if self.wrap_required:
            # Type guard: Ensure encryption is initialized before use
            if self.encryption is None:
                raise WinRMTransportError(
                    500,
                    "Encryption required but not initialized",
                )
            
            content_type: str
            payload: bytes
            content_type, payload = self.encryption.wrap_message(message)
            protocol_str: typing.Union[str, None] = (
                self.encryption.protocol if self.encryption else WinRMEncryption.SPNEGO
            )
            type_header: str = '%s;protocol="%s";boundary="Encrypted Boundary"' % (
                content_type,
                protocol_str,
            )
            headers.update(
                {
                    "Content-Type": type_header,
                    "Content-Length": str(len(payload)),
                }
            )
        else:
            payload = message
            headers["Content-Type"] = "application/soap+xml;charset=UTF-8"

        request = requests.Request("POST", self.endpoint, data=payload, headers=headers)
        prep_request = self.session.prepare_request(request)
        
        try:
            return self._send_request(prep_request)
        except WinRMTransportError as err:
            # Implement session reset on 400 errors (stale session)
            if hasattr(err, 'code') and err.code == 400:
                logger.debug("Session invalid (400 error), resetting session and retrying")
                self.session = None
                return self.send(message)
            else:
                raise

    def _build_session(self) -> requests.Session:
        """
        Build a requests session with enhanced configuration.

        Returns:
            Configured requests.Session object
        """
        logger.debug("Building requests session with auth %s", self.auth)
        self._suppress_library_warnings()

        session = requests.Session()
        session.headers["User-Agent"] = self.user_agent

        # Set Accept-Encoding to identity to prevent compression issues
        # This is critical for IIS/Exchange endpoints that may compress responses
        session.headers["Accept-Encoding"] = "identity"

        # Get environment requests settings
        session.trust_env = True
        settings = session.merge_environment_settings(
            url=self.endpoint, proxies={}, stream=None, verify=None, cert=None
        )

        # Configure proxy settings
        session.proxies = settings["proxies"]
        proxy_key = "https" if self.ssl else "http"
        if self.proxy is not None:
            session.proxies = {proxy_key: self.proxy}
        elif self.no_proxy:
            # Set empty dict to disable proxy
            session.proxies = {}

        # Configure retry logic with exponential backoff
        retry_kwargs = {
            "total": self.reconnection_retries,
            "connect": self.reconnection_retries,
            "read": 0,
            "backoff_factor": self.reconnection_backoff,
            "status_forcelist": (425, 429, 503),
        }
        
        try:
            # Try with status parameter (urllib3 >= 1.21)
            retry_kwargs["status"] = self.reconnection_retries
            retries = Retry(**retry_kwargs)
        except TypeError:
            # Fall back for older urllib3 versions
            logger.warning(
                "Using older urllib3 version without status retry support. "
                "Consider upgrading to urllib3 >= 1.21 (requests >= 2.14.0)"
            )
            del retry_kwargs["status"]
            retries = Retry(**retry_kwargs)

        session.mount("http://", requests.adapters.HTTPAdapter(max_retries=retries))
        session.mount("https://", requests.adapters.HTTPAdapter(max_retries=retries))

        # Configure certificate validation
        session.verify = self.cert_validation
        if (
            isinstance(self.cert_validation, bool)
            and self.cert_validation
            and settings["verify"] is not None
        ):
            session.verify = settings["verify"]

        # Build authentication based on auth type
        build_auth = getattr(self, "_build_auth_%s" % self.auth)
        build_auth(session)
        
        return session
