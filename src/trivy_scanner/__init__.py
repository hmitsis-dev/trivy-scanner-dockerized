"""Self-hosted Trivy scanning service and CI client."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("trivy-scanner-api")
except PackageNotFoundError:  # pragma: no cover - running from a source checkout
    __version__ = "0.0.0"

__all__ = ["__version__"]
