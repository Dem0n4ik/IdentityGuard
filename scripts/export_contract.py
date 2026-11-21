import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from app.api import create_app
from app.repository import Repository

destination = Path("api/openapi.yaml")
with TemporaryDirectory() as directory:
    schema = create_app(Repository(Path(directory) / "contract.sqlite")).openapi()
rendered = json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

if "--check" in sys.argv:
    if destination.read_text(encoding="utf-8") != rendered:
        raise SystemExit("OpenAPI contract drift detected")
else:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered, encoding="utf-8", newline="\n")
