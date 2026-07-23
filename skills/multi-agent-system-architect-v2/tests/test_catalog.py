from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_catalog_is_dated_primary_source_data_without_rankings() -> None:
    catalog = yaml.safe_load((ROOT / "assets/framework_catalog.yaml").read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "assets/schemas/contracts.schema.json").read_text(encoding="utf-8"))
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/frameworkCatalog", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator(wrapper, format_checker=jsonschema.FormatChecker()).validate(catalog)
    assert len(catalog["candidates"]) == 7
    assert sum(len(item["official_sources"]) for item in catalog["candidates"]) == 16
    assert catalog["tech_watch"]["cadence_days"] <= 92
    assert date.fromisoformat(catalog["tech_watch"]["next_due"]) > date.fromisoformat(catalog["verified_at"])
    allowed_hosts = {
        "openai.github.io",
        "adk.dev",
        "learn.microsoft.com",
        "docs.langchain.com",
        "agentskills.io",
        "modelcontextprotocol.io",
        "a2a-protocol.org",
    }
    forbidden = {"price", "stars", "ranking", "editorial_score", "automatic_winner"}
    for candidate in catalog["candidates"]:
        assert not forbidden.intersection(candidate)
        assert candidate["object_categories"]
        assert candidate["official_sources"]
        for source in candidate["official_sources"]:
            assert urlparse(source["url"]).hostname in allowed_hosts
            assert source["supports"]
