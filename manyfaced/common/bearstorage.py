import logging
import socket

# type placeholders for type checkers
ipinfo_dummy = None  # placeholder if ipinfo is used in future

logger = logging.getLogger(__name__)


class BearStorage:
    """Stores bear (bot) data gathered from a connection."""

    def __init__(
        self,
        ip: str,
        raw_request: str,
        timestamp: str,
        parsed_request: object,
        is_detected: int,
        hostname: str,
    ) -> None:
        self.ip = ip
        self.raw_request = raw_request
        self.timestamp = timestamp
        self.path = ""
        self.command = ""
        self.version = ""
        self.ua = ""
        self.headers = ""  # type: ignore[assignment]
        self.country = ""
        self.continent = ""
        self.timezone = ""
        self.dns_name = ""
        self.tracert = ""  # TODO
        if hasattr(parsed_request, "path"):
            self.path = parsed_request.path
        if getattr(parsed_request, "command", None) is not None:
            self.command = parsed_request.command
        if hasattr(parsed_request, "request_version"):
            self.version = parsed_request.request_version
        if hasattr(parsed_request, "headers"):
            self.headers = parsed_request.headers
            # HTTPMessage supports case-insensitive lookups via .get()
            ua_val = None
            if isinstance(parsed_request.headers, dict):
                ua_val = parsed_request.headers.get("user-agent") or parsed_request.headers.get("User-Agent", "")
            else:
                # http.client.HTTPMessage — use get() for case-insensitive lookup
                ua_val = parsed_request.headers.get("user-agent") or parsed_request.headers.get("User-Agent", "")
            if ua_val:
                self.ua = ua_val
        self.isDetected = is_detected
        self.hostname = hostname
        # Reverse-DNS and geolocation moved to async context (see resolve_dns_name, resolve_geo)

    def resolve_dns_name(self, ip: str, timeout: float = 1.0) -> str:
        """Resolve reverse-DNS for *ip* with a short timeout.

        Returns the hostname on success, empty string on failure or timeout.
        """
        try:
            socket.setdefaulttimeout(timeout)
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.timeout, socket.gaierror, OSError):
            return ""
        finally:
            socket.setdefaulttimeout(None)

    def resolve_geo(self, ip: str, timeout: float = 2.0) -> tuple[str, str]:
        """Look up country and continent for *ip* via ip-api.com.

        Non-blocking: catches all exceptions and returns ("", "").
        Results are cached internally to respect rate limits.

        Args:
            ip: IP address string.
            timeout: HTTP request timeout in seconds.

        Returns:
            Tuple of (country_name, continent_code), e.g. ("United States", "NA").
        """
        try:
            from manyfaced.common.geolocate import lookup_ip_geolocation
            country, continent = lookup_ip_geolocation(ip, timeout=timeout)
            self.country = country
            self.continent = continent
            return (country, continent)
        except Exception as e:
            logger.debug("Geo resolution failed for %s: %s", ip, e)
            return ("", "")

    def __str__(self) -> str:
        if self.path != "":
            output = (
                "hostname: " + self.hostname + "\r\n"
                "IP: " + self.ip + "\r\n"
                "timestamp: " + self.timestamp + "\r\n"
                "User-Agent: " + self.ua + "\r\n"
                "datected: " + str(self.isDetected) + "\r\n"
                "path: " + self.path + "\r\n"
                "command: " + self.command + "\r\n"
                "version: " + self.version + "\r\n"
                "country: " + self.country + "\r\n"
            )
            if self.isDetected != 4294967295 - 3:
                output += "Detected: Yes" + "\r\n"
            else:
                output += "Detected: No" + "\r\n"
        else:
            output = (
                "hostname: " + self.hostname + "\r\n"
                "IP: " + self.ip + "\r\n"
                "timestamp: " + self.timestamp + "\r\n"
                "raw_request: " + self.raw_request + "\r\n"
                "country: " + self.country + "\r\n"
            )
        return output

    def __repr__(self) -> str:
        return self.__str__()
