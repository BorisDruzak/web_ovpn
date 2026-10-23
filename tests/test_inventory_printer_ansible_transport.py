"""Exercise real Ansible templating and command stdin, not just YAML text."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml


def test_real_ansible_transmits_printer_payload_as_json(tmp_path):
    executable = shutil.which("ansible-playbook")
    if not executable:
        pytest.skip("Linux Ansible runtime required")
    source = Path(__file__).resolve().parents[1] / "deploy/alt-linux/ansible"
    role = source / "roles/inventory_printers"
    catalog = json.loads((role / "files/driver_catalog.json").read_text())
    driver = catalog["M2030DN"]
    (tmp_path / driver["filename"]).write_bytes(b"transport-only-test")
    tasks = yaml.safe_load((role / "tasks/main.yml").read_text())[:2]
    tasks[1]["ansible.builtin.command"]["argv"] = [
        "/usr/bin/python3",
        "-c",
        'import json,sys; v=json.load(sys.stdin); assert v["request"]["printers"][0]["model"]=="M2030DN"; print("valid-json")',
    ]
    tasks.append(
        {
            "ansible.builtin.assert": {
                "that": [
                    "inventory_printer_validation.rc == 0",
                    'inventory_printer_validation.stdout == "valid-json"',
                ]
            }
        }
    )
    play = tmp_path / "play.yml"
    play.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": {
                        "role_path": str(role),
                        "inventory_printer_driver_dir": str(tmp_path),
                        "inventory_printer_request": {
                            "printers": [{"model": "M2030DN", "driver": driver}]
                        },
                    },
                    "tasks": tasks,
                }
            ]
        )
    )
    config = tmp_path / "ansible.cfg"
    config.write_text(
        "[defaults]\nfilter_plugins=" + str(source / "filter_plugins") + "\n"
    )
    result = subprocess.run(
        [executable, "-i", "localhost,", str(play)],
        cwd=tmp_path,
        env=dict(os.environ, ANSIBLE_CONFIG=str(config)),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
