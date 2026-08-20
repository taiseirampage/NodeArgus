import io
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import geoip2.database
import pytest
import requests

from app.geo.downloader import GeoIPDownloader
from app.geo.geoip import GeoIPService
from app.scanner.enricher import enrich_scan_result
from app.scanner.models import MasscanResult


def _geo_response() -> SimpleNamespace:
    return SimpleNamespace(
        country=SimpleNamespace(name="United States", iso_code="US"),
        city=SimpleNamespace(name="Ashburn"),
        location=SimpleNamespace(
            latitude=39.0438, longitude=-77.4874, time_zone="America/New_York"
        ),
        traits=SimpleNamespace(isp="Example ISP"),
    )


def test_lookup_uses_geoip2_reader(tmp_path: Path) -> None:
    reader = MagicMock()
    reader.city.return_value = _geo_response()
    with patch.object(geoip2.database, "Reader", return_value=reader):
        service = GeoIPService(str(tmp_path / "GeoLite2-City.mmdb"))
        location = service.lookup("8.8.8.8")

    assert location is not None
    assert location.country_code == "US"
    assert location.isp == "Example ISP"
    reader.city.assert_called_once_with("8.8.8.8")


@pytest.mark.parametrize("ip", ["192.168.1.1", "10.0.0.1"])
def test_lookup_skips_private_ips(tmp_path: Path, ip: str) -> None:
    reader = MagicMock()
    with patch.object(geoip2.database, "Reader", return_value=reader):
        service = GeoIPService(str(tmp_path / "GeoLite2-City.mmdb"))
        assert service.lookup(ip) is None
    reader.city.assert_not_called()


def test_lookup_batch_omits_unknown_addresses(tmp_path: Path) -> None:
    reader = MagicMock()
    reader.city.return_value = _geo_response()
    with patch.object(geoip2.database, "Reader", return_value=reader):
        service = GeoIPService(str(tmp_path / "GeoLite2-City.mmdb"))
        locations = service.lookup_batch(["8.8.8.8", "192.168.1.1"])

    assert list(locations) == ["8.8.8.8"]


def test_missing_database_raises_clear_error(tmp_path: Path) -> None:
    with patch.object(geoip2.database, "Reader", side_effect=FileNotFoundError):
        with pytest.raises(FileNotFoundError, match="GeoIP database was not found"):
            GeoIPService(str(tmp_path / "missing.mmdb"))


def test_downloader_extracts_database_from_mocked_response(tmp_path: Path) -> None:
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
        database = b"mock-mmdb"
        info = tarfile.TarInfo("GeoLite2-City_2026/GeoLite2-City.mmdb")
        info.size = len(database)
        archive.addfile(info, io.BytesIO(database))
    response = MagicMock()
    response.headers = {"content-length": str(len(archive_buffer.getvalue()))}
    response.iter_content.return_value = [archive_buffer.getvalue()]
    response.__enter__.return_value = response

    downloader = GeoIPDownloader(license_key="test-key", download_dir=str(tmp_path))
    with patch("app.geo.downloader.requests.get", return_value=response) as get:
        assert downloader.download_city_db() is True

    get.assert_called_once()
    response.raise_for_status.assert_called_once_with()
    assert downloader.db_path.read_bytes() == b"mock-mmdb"


def test_downloader_handles_network_errors(tmp_path: Path) -> None:
    downloader = GeoIPDownloader(license_key="test-key", download_dir=str(tmp_path))
    with patch(
        "app.geo.downloader.requests.get",
        side_effect=requests.exceptions.ConnectionError("offline"),
    ):
        assert downloader.download_city_db() is False


def test_update_check_uses_thirty_day_threshold(tmp_path: Path) -> None:
    database = tmp_path / "GeoLite2-City.mmdb"
    database.write_bytes(b"db")
    old_time = (datetime.now(timezone.utc) - timedelta(days=31)).timestamp()
    database.touch()
    import os

    os.utime(database, (old_time, old_time))
    assert GeoIPDownloader(download_dir=str(tmp_path)).check_update_needed() is True


def test_enricher_attaches_geo_data() -> None:
    result = MasscanResult(target="8.8.8.8", scanned_ports=[], scan_time=0.1)
    location = _geo_response()
    geo = MagicMock()
    geo.lookup.return_value = SimpleNamespace(
        ip="8.8.8.8",
        country=location.country.name,
        country_code=location.country.iso_code,
        city=location.city.name,
        latitude=location.location.latitude,
        longitude=location.location.longitude,
        timezone=location.location.time_zone,
        isp=location.traits.isp,
    )

    enriched = enrich_scan_result(result, geo)

    assert enriched.geo is not None
    geo.lookup.assert_called_once_with("8.8.8.8")
