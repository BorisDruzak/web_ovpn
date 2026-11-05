"""Separate root-only acceptance for read-only native CLI planning."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='native protected-source CLI requires root')


def test_native_plan_creates_neither_source_bytecode_nor_evidence_cache():
    scratch = Path(tempfile.mkdtemp(prefix='alt-release-cli-test-', dir='/opt'))
    scratch.chmod(0o755)
    try:
        source, cache = scratch/'source', scratch/'cache'
        shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('.git', '.venv', '.superpowers', '__pycache__', '.pytest_cache'))
        for path in [source, *source.rglob('*')]:
            if path.is_dir(): path.chmod(0o755)
            else: path.chmod(0o644)
        result = subprocess.run([sys.executable, '-I', str(source/'deploy/alt-linux/verification_checkpoint.py'),
            '--source', str(source), '--cache', str(cache), '--python', '/usr/bin/python3', '--plan'],
            capture_output=True, text=True, timeout=180)
        assert result.returncode == 0, result.stdout + result.stderr
        value = json.loads(result.stdout)
        assert value['mode'] == 'full' and value['verification'] == 'planned'
        assert value['rollout_authorized'] is False
        assert not cache.exists()
        assert not list(source.rglob('__pycache__'))
    finally:
        assert scratch.resolve().parent == Path('/opt') and scratch.name.startswith('alt-release-cli-test-')
        shutil.rmtree(scratch)
