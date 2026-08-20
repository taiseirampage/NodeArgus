from pathlib import Path
import sys

import click

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.geo.downloader import GeoIPDownloader
from app.config import settings


@click.command()
@click.option("--license-key", default=None, help="MaxMind GeoLite license key.")
@click.option(
    "--output-dir",
    default="data",
    show_default=True,
    type=click.Path(file_okay=False, dir_okay=True, path_type=str),
)
def main(license_key: str | None, output_dir: str) -> None:
    """Download the local GeoLite2-City database."""
    downloader = GeoIPDownloader(
        license_key=license_key or settings.GEOIP_LICENSE_KEY,
        download_dir=output_dir,
    )
    if not downloader.download_city_db():
        raise click.ClickException("GeoIP database is unavailable")
    path = downloader.db_path
    click.echo(f"GeoIP database: {path}")
    click.echo(f"Size: {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
