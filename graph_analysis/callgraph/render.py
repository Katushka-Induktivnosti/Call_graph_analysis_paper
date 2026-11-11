from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def render_html(graph: dict[str, Any], output_folder: Path, template_path: Path) -> Path:
    template = template_path.read_text(encoding="utf-8")
    html = template.replace("__GRAPH_DATA__", json.dumps(graph, ensure_ascii=False))
    output_path = output_folder / "index.html"
    output_path.write_text(html, encoding="utf-8")
    return output_path

