"""Export backend OpenAPI schema to docs/openapi.json."""

import json
import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Ensure HMAC_SECRET is present so get_settings() succeeds
if not os.getenv("HMAC_SECRET"):
    os.environ["HMAC_SECRET"] = "openapi-export-temporary-secret-32chars!"

from backend.main import create_app


def export_openapi(output_path: str = "docs/openapi.json"):
    app = create_app()
    openapi_schema = app.openapi()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(openapi_schema, f, indent=2)
    print(f"Exported OpenAPI specification successfully to {output_path}")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "docs/openapi.json"
    export_openapi(out)
