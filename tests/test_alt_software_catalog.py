from pathlib import Path

import yaml


CATALOG = Path(__file__).parents[1] / "deploy" / "alt-linux" / "ansible" / "group_vars" / "software_catalog.yml"


def test_catalog_components_are_disabled_or_complete() -> None:
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["software_catalog"]
    assert set(catalog) == {"browser", "onlyoffice", "nextcloud_desktop"}
    for name, item in catalog.items():
        if item["enabled"]:
            assert item["source"] in {"rpm", "alt-repository"}, name
            assert {"enabled", "source", "executable"} <= set(item), name
            assert isinstance(item["executable"], str) and item["executable"], name
            if item["source"] == "rpm":
                assert {"artifact_path", "sha256", "package_name", "package_evr", "architecture"} <= set(item), name
            else:
                assert isinstance(item.get("packages"), list) and item["packages"], name
