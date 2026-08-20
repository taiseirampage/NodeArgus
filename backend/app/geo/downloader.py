import logging
import os
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests


logger = logging.getLogger(__name__)
_DATABASE_NAME = "GeoLite2-City.mmdb"
_MAXMIND_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"
)


class GeoIPDownloader:
    """Download and refresh a local MaxMind GeoLite2-City database."""

    def __init__(
        self, license_key: str | None = None, download_dir: str = "data"
    ) -> None:
        """Initialize the downloader.

        Args:
            license_key: Optional MaxMind license key for official downloads.
            download_dir: Directory where the MMDB file is stored.
        """
        self.license_key = license_key
        self.download_dir = Path(download_dir)
        self.db_path = self.download_dir / _DATABASE_NAME

    def check_update_needed(self) -> bool:
        """Return whether the database is missing or older than 30 days."""
        if not self.db_path.is_file():
            return True
        modified_at = datetime.fromtimestamp(
            self.db_path.stat().st_mtime, tz=timezone.utc
        )
        return datetime.now(timezone.utc) - modified_at > timedelta(days=30)

    def download_city_db(self) -> bool:
        """Download GeoLite2-City from MaxMind or use an existing local file.

        Returns:
            True when a usable local database is available, otherwise False.
        """
        if not self.license_key and self.db_path.is_file():
            logger.info("Using existing local GeoIP database: %s", self.db_path)
            return True

        url = self._download_url()
        if url is None:
            logger.warning(
                "No license key, mirror URL, or local GeoIP database is available: %s",
                self.db_path,
            )
            return False

        self.download_dir.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            temporary_path = self._download_archive(url)
            self._extract_database(temporary_path)
            logger.info("GeoIP database downloaded to %s", self.db_path)
            return True
        except requests.exceptions.RequestException as error:
            logger.error("GeoIP database download failed: %s", error)
            return False
        except (OSError, tarfile.TarError, ValueError) as error:
            logger.error("GeoIP database processing failed: %s", error)
            return False
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def update_if_needed(self) -> bool:
        """Update the database when it is missing or older than 30 days."""
        if not self.check_update_needed():
            logger.info("GeoIP database is current: %s", self.db_path)
            return True
        return self.download_city_db()

    def _download_url(self) -> str | None:
        if self.license_key:
            return _MAXMIND_URL.format(license_key=self.license_key)
        return os.environ.get("GEOIP_MIRROR_URL")

    def _download_archive(self, url: str) -> Path:
        with requests.get(url, stream=True, timeout=60) as response:
            response.raise_for_status()
            with tempfile.NamedTemporaryFile(
                dir=self.download_dir,
                prefix="GeoLite2-City-",
                suffix=".tar.gz",
                delete=False,
            ) as temporary_file:
                archive_path = Path(temporary_file.name)
                total = int(response.headers.get("content-length", 0))
                downloaded = 0
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    temporary_file.write(chunk)
                    downloaded += len(chunk)
                    self._log_progress(downloaded, total)
        return archive_path

    @staticmethod
    def _log_progress(downloaded: int, total: int) -> None:
        if total > 0:
            logger.info("GeoIP download progress: %.1f%%", downloaded * 100 / total)
        else:
            logger.info("GeoIP download progress: %d bytes", downloaded)

    def _extract_database(self, archive_path: Path) -> None:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            database_member = next(
                (
                    member
                    for member in archive.getmembers()
                    if Path(member.name).name == _DATABASE_NAME and member.isfile()
                ),
                None,
            )
            if database_member is None:
                raise ValueError(f"Archive does not contain {_DATABASE_NAME}")
            extracted = archive.extractfile(database_member)
            if extracted is None:
                raise ValueError(f"Unable to read {_DATABASE_NAME} from archive")
            self.db_path.write_bytes(extracted.read())
