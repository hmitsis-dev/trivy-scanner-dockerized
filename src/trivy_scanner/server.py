"""`trivy-scanner-server` entry point: run the API with uvicorn."""

from __future__ import annotations

import argparse
import logging
import os


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Trivy scanner API (configured via environment variables)")
    parser.add_argument("--host", default=os.getenv("HOST", "0.0.0.0"), help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")), help="Bind port (default: 8000)")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "info"), help="Log level (default: info)")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        parser.exit(1, "The server needs extra dependencies: pip install 'trivy-scanner-api[server]'\n")

    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    uvicorn.run(
        "trivy_scanner.api:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
