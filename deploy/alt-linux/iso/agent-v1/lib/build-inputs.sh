#!/bin/bash

snapshot_public_key() {
    local source="$1" destination="$2" temporary size
    [[ -f "$source" && -r "$source" ]] || return 1
    [[ -d "${destination%/*}" && ! -L "${destination%/*}" ]] || return 1
    [[ ! -e "$destination" && ! -L "$destination" ]] || return 1
    temporary="${destination}.tmp.$$"
    [[ ! -e "$temporary" && ! -L "$temporary" ]] || return 1
    if ! (
        umask 077
        cat -- "$source" > "$temporary"
    ); then
        rm -f -- "$temporary"
        return 1
    fi
    [[ -f "$temporary" && ! -L "$temporary" ]] || {
        rm -f -- "$temporary"
        return 1
    }
    size=$(wc -c < "$temporary") || {
        rm -f -- "$temporary"
        return 1
    }
    [[ "$size" -ge 1 && "$size" -le 4096 ]] || {
        rm -f -- "$temporary"
        return 1
    }
    chmod 0600 -- "$temporary"
    mv -f -- "$temporary" "$destination"
    chmod 0600 -- "$destination"
}

public_key_metadata() {
    local snapshot="$1" python_command=${ALT_INSTALL_PYTHON:-python3}
    [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 1
    "$python_command" - "$snapshot" <<'PY'
import base64
import hashlib
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
raw_document = path.read_bytes()
try:
    text = raw_document.decode("utf-8")
except UnicodeDecodeError as exc:
    raise SystemExit("public key JSON is invalid") from exc

def object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate public key field")
        result[key] = value
    return result

try:
    document = json.loads(text, object_pairs_hook=object_without_duplicates)
except (ValueError, json.JSONDecodeError) as exc:
    raise SystemExit("public key JSON is invalid") from exc
if set(document) != {
    "schema_version", "algorithm", "key_id", "public_key_b64"
}:
    raise SystemExit("public key fields are invalid")
if document["schema_version"] != 1 or document["algorithm"] != "ed25519":
    raise SystemExit("public key metadata is invalid")
encoded = document.get("public_key_b64")
if not isinstance(encoded, str):
    raise SystemExit("public key value is invalid")
try:
    raw_key = base64.b64decode(encoded, validate=True)
except (TypeError, ValueError) as exc:
    raise SystemExit("public key value is invalid") from exc
if len(raw_key) != 32 or base64.b64encode(raw_key).decode("ascii") != encoded:
    raise SystemExit("public key value is invalid")
key_id = "sha256:" + hashlib.sha256(raw_key).hexdigest()
if document["key_id"] != key_id:
    raise SystemExit("public key ID is invalid")
print(key_id, hashlib.sha256(raw_document).hexdigest())
PY
}
