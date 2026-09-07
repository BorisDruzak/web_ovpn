from pathlib import Path

import yaml


CATALOG = Path(__file__).parents[1] / "deploy" / "alt-linux" / "ansible" / "group_vars" / "software_catalog.yml"


def test_core_apps_catalog_enables_only_controller_verified_artifacts() -> None:
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["software_catalog"]
    assert catalog["browser"] == {
        "enabled": True, "source": "rpm",
        "artifact_path": "/opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm",
        "sha256": "7fbce78e9799ae36ebfcf750d5880f27d829d5546e9ac77f1868afb9657d9a89",
        "package_name": "yandex-browser-stable", "package_evr": "26.4.4.968-1",
        "architecture": "x86_64", "executable": "/usr/bin/yandex-browser-stable",
    }
    assert catalog["onlyoffice"] == {
        "enabled": True, "source": "rpm",
        "artifact_path": "/opt/alt-deploy-control/artifacts/onlyoffice/onlyoffice-desktopeditors-9.4.0-epm1.repacked.130.x86_64.rpm",
        "sha256": "b8dd26405b5cd79da8a80afc7089007de608a53e7e90ea6a247379bebfe54c9f",
        "package_name": "onlyoffice-desktopeditors", "package_evr": "9.4.0-epm1.repacked.130",
        "architecture": "x86_64", "executable": "/usr/bin/onlyoffice-desktopeditors",
    }
    assert catalog["nextcloud_desktop"] == {
        "enabled": True, "source": "alt-repository",
        "packages": ["nextcloud-client", "nextcloud-client-kde"],
        "executable": "/usr/bin/nextcloud",
    }


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
