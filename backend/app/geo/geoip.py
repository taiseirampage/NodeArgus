import ipaddress
import logging
from functools import lru_cache

import geoip2.database
from geoip2.errors import AddressNotFoundError

from .models import GeoLocation


logger = logging.getLogger(__name__)


class GeoIPService:
    """Look up IP geolocation data in a local MaxMind City database."""

    def __init__(self, db_path: str = "data/GeoLite2-City.mmdb") -> None:
        """Initialize a MaxMind reader for the configured database path.

        Args:
            db_path: Path to a local GeoLite2-City or GeoIP2-City database.

        Raises:
            FileNotFoundError: If the database path does not exist.
            RuntimeError: If the geoip2 package cannot create a reader.
        """
        self.db_path = db_path
        try:
            self.reader = geoip2.database.Reader(db_path)
        except FileNotFoundError as error:
            raise FileNotFoundError(
                f"GeoIP database was not found: {db_path}. "
                "Download GeoLite2-City.mmdb before performing lookups."
            ) from error
        except (OSError, TypeError, ValueError) as error:
            raise RuntimeError(
                f"Unable to open GeoIP database '{db_path}': {error}"
            ) from error

    def close(self) -> None:
        """Close the underlying MaxMind database reader."""
        self.lookup.cache_clear()
        self.reader.close()

    def __enter__(self) -> "GeoIPService":
        """Enter a context manager and return this service."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the reader when leaving a context manager."""
        self.close()

    @lru_cache(maxsize=4096)
    def lookup(self, ip: str) -> GeoLocation | None:
        """Find geolocation data for one public IP address.

        Args:
            ip: A textual IPv4 or IPv6 address.

        Returns:
            GeoLocation data, or None for private, invalid, or unknown addresses.
        """
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("Skipping invalid IP address: %s", ip)
            return None
        if address.is_private or address.is_loopback or address.is_reserved:
            return None
        try:
            response = self.reader.city(str(address))
        except AddressNotFoundError:
            logger.info("IP address is not present in GeoIP database: %s", address)
            return None
        except (OSError, ValueError) as error:
            logger.warning("GeoIP lookup failed for %s: %s", address, error)
            return None

        location = response.location
        country = response.country
        city = response.city
        traits = response.traits
        return GeoLocation(
            ip=str(address),
            country=country.name or "",
            country_code=country.iso_code or "",
            city=city.name or "",
            latitude=location.latitude or 0.0,
            longitude=location.longitude or 0.0,
            timezone=location.time_zone or "",
            isp=traits.isp or "",
        )

    def lookup_batch(self, ips: list[str]) -> dict[str, GeoLocation]:
        """Look up multiple IP addresses and omit unknown addresses.

        Args:
            ips: List of textual IPv4 or IPv6 addresses.

        Returns:
            A mapping of the original IP strings to discovered locations.
        """
        locations: dict[str, GeoLocation] = {}
        for ip in ips:
            location = self.lookup(ip)
            if location is not None:
                locations[ip] = location
        return locations
