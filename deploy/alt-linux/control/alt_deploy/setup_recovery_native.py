"""Fixed offline Samba commands and strict evidence parsers.

These helpers do not install authentication files or contact a directory.  The
only writable mount is a caller-owned private rehearsal directory.  They are
not an execution entry point for recovery.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import uuid

_FIELDS = frozenset(("hostname", "realm", "workgroup", "domain_guid",
                     "domain_sid", "dc_hostname", "dc_address"))
_AES = frozenset(("aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"))


def validate_metadata(meta: dict) -> dict:
    if not isinstance(meta, dict) or set(meta) != _FIELDS or any(
            not isinstance(value, str) for value in meta.values()):
        raise ValueError("invalid recovery metadata")
    if (not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", meta["hostname"])
            or len(meta["hostname"]) > 15
            or meta["realm"] != "sosnadmin.local"
            or meta["workgroup"] != "SOSNADM"
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.sosnadmin\.local",
                                meta["dc_hostname"])
            or not re.fullmatch(r"S-1-5-21-(?:[1-9][0-9]*-){2}[1-9][0-9]*",
                                meta["domain_sid"])):
        raise ValueError("invalid recovery metadata")
    try:
        if str(uuid.UUID(meta["domain_guid"])) != meta["domain_guid"]:
            raise ValueError()
        address = ipaddress.IPv4Address(meta["dc_address"])
        if str(address) != meta["dc_address"] or address.is_multicast or address.is_unspecified:
            raise ValueError()
        if any(int(item) > 0xffffffff for item in meta["domain_sid"].split("-")[4:]):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError("invalid recovery metadata") from None
    return dict(meta)


def sandbox_config(meta: dict) -> str:
    meta = validate_metadata(meta)
    return ("[global]\nsecurity = ads\nserver role = member server\n"
            f"workgroup = {meta['workgroup']}\nrealm = {meta['realm'].upper()}\n"
            f"netbios name = {meta['hostname'].upper()}\n"
            "private dir = /work/private\nstate directory = /work/state\n"
            "cache directory = /work/cache\nlock directory = /work/lock\n"
            "pid directory = /work/pid\nlog file = /work/logs/log.%m\n"
            "ncalrpc dir = /work/ncalrpc\nwinbindd socket directory = /work/winbind\n"
            "passdb backend = tdbsam:/work/private/passdb.tdb\n"
            "kerberos method = secrets only\n"
            "sync machine password to keytab = disabled\nsync machine password script =\n")


def sandbox_command(work: Path, meta: dict, operation: str, *, owner: int = 0) -> list[str]:
    meta = validate_metadata(meta)
    work = Path(work)
    if not work.is_absolute():
        raise ValueError("invalid rehearsal directory")
    # Resolve every component without following links.  A writable parent allows
    # replacement of the private leaf even when the leaf itself is mode 0700.
    for path in (work, *work.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("invalid rehearsal directory")
        if path == work and (info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("invalid rehearsal directory")
        if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise ValueError("invalid rehearsal directory")
    net = ["/usr/bin/net", "-s", "/work/smb.conf", "-d", "0"]
    if operation == "compose":
        native = net + ["-A", "/dev/stdin", "-S", meta["dc_hostname"], "-I", meta["dc_address"],
                        "offlinejoin", "composeodj", f"domain_sid={meta['domain_sid']}",
                        f"domain_guid={meta['domain_guid']}", f"forest_name={meta['realm']}", "printblob"]
    elif operation == "import":
        native = net + ["-i", "offlinejoin", "requestodj"]
    elif operation == "metadata":
        native = net + ["primarytrust", "dumpinfo"]
    elif operation == "password":
        native = net + ["-i", "-f", "changesecretpw"]
    elif operation == "keytab":
        native = net + ["--option", "sync machine password to keytab=/work/krb5.keytab:account_name:"
                        f"spns=host/{meta['hostname']}.{meta['realm']}:machine_password",
                        "ads", "keytab", "create"]
    elif operation == "keytab_list":
        native = net + ["ads", "keytab", "list", "/work/krb5.keytab"]
    elif operation == "password_check":
        # Read-only legacy TDB verification; native Samba remains the only
        # writer.  Never emit the password or any database content.
        native = ["/usr/bin/python3", "-I", "-B", "-c",
                  "import hmac,os,re,sys,tdb; "
                  "password=sys.stdin.buffer.read(69); "
                  "assert re.fullmatch(rb'Aa9![A-Za-z0-9_-]{64}',password); "
                  "database=tdb.open('/work/private/secrets.tdb',flags=os.O_RDONLY); "
                  "value=database.get(b'SECRETS/MACHINE_PASSWORD/SOSNADM'); "
                  "ok=isinstance(value,bytes) and hmac.compare_digest(value,password+b'\\0'); "
                  "database.close(); print('true' if ok else 'false'); sys.exit(0 if ok else 1)"]
    else:
        raise ValueError("invalid rehearsal operation")
    return (["/usr/bin/bwrap", "--unshare-user", "--unshare-net", "--unshare-pid",
             "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session",
             "--cap-drop", "ALL", "--clearenv", "--setenv", "LC_ALL", "C.UTF-8",
             "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
             "--ro-bind", "/lib64", "/lib64", "--dir", "/etc",
             "--ro-bind", "/etc/passwd", "/etc/passwd", "--ro-bind", "/etc/group", "/etc/group",
             "--ro-bind", "/etc/nsswitch.conf", "/etc/nsswitch.conf", "--dev", "/dev",
             "--proc", "/proc", "--tmpfs", "/tmp", "--bind", str(work), "/work",
             "--chdir", "/work", "--"] + native)


def validate_native_metadata(raw: str, meta: dict) -> bool:
    meta = validate_metadata(meta)
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 16384 or "\x00" in raw:
        raise ValueError("invalid native metadata")
    # Parse the native indentation tree rather than searching for matching
    # strings anywhere in the output (old passwords contain other structures).
    entries: dict[tuple[str, ...], list[str]] = {}
    stack: list[tuple[int, str]] = []
    lines = raw.splitlines()
    if lines and lines[-1] == "The password values are only included using -f flag.":
        lines.pop()
    for line in lines:
        flag = re.fullmatch(r" {23}[01]: ([A-Z0-9_]+) *", line)
        if flag is not None:
            prefixes = {"trust_flags": "NETR_TRUST_FLAG_", "trust_attributes": "LSA_TRUST_ATTRIBUTE_",
                        "supported_enc_types": "KERB_ENCTYPE_"}
            if (not stack or stack[-1][0] != 16 or stack[-1][1] not in prefixes
                    or not flag[1].startswith(prefixes[stack[-1][1]])):
                raise ValueError("invalid native metadata")
            continue
        match = re.fullmatch(r"( +)([A-Za-z0-9_]+)\s*: (.+)", line)
        if match is None:
            raise ValueError("invalid native metadata")
        indent, label, value = len(match[1]), match[2], match[3]
        if indent % 4 or indent < 4:
            raise ValueError("invalid native metadata")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if indent != (stack[-1][0] + 4 if stack else 4):
            raise ValueError("invalid native metadata")
        key = tuple(item[1] for item in stack) + (label,)
        entries.setdefault(key, []).append(value)
        stack.append((indent, label))
    root = (meta["workgroup"],)
    base = root + ("info1", "info1")
    expected = {
        root: "struct secrets_domain_infoB",
        root + ("version",): "SECRETS_DOMAIN_INFO_VERSION_1 (1)",
        root + ("info",): "union secrets_domain_infoU(case 1)",
        root + ("info1",): "*", base: "struct secrets_domain_info1",
        base + ("computer_name",): repr(meta["hostname"].upper()),
        base + ("account_name",): repr(meta["hostname"].upper() + "$"),
        base + ("secure_channel_type",): "SEC_CHAN_WKSTA (2)",
        base + ("domain_info",): "struct lsa_DnsDomainInfo",
        base + ("domain_info", "domain_guid"): meta["domain_guid"],
        base + ("domain_info", "sid"): "*",
        base + ("domain_info", "sid", "sid"): meta["domain_sid"],
        base + ("salt_principal",): "*",
        base + ("salt_principal", "salt_principal"): repr(
            f"host/{meta['hostname']}.{meta['realm']}@{meta['realm'].upper()}"),
        base + ("next_change",): "NULL",
        base + ("password",): "*",
        base + ("password", "password"): "struct secrets_domain_info1_password",
    }
    for field, value in (("name", meta["workgroup"]), ("dns_domain", meta["realm"]),
                         ("dns_forest", meta["realm"])):
        prefix = base + ("domain_info", field)
        expected[prefix] = "struct lsa_StringLarge"
        expected[prefix + ("string",)] = "*"
        expected[prefix + ("string", "string")] = repr(value)
    for field in ("dns_domain", "dns_forest"):
        key = base + ("domain_info", field, "string", "string")
        values = entries.get(key)
        if values is not None and len(values) == 1 and re.fullmatch(r"'[A-Za-z0-9.]+'", values[0]):
            entries[key] = [values[0].lower()]
    if any(entries.get(key) != [value] for key, value in expected.items()) or any(
            key[0] != meta["workgroup"] for key in entries):
        raise ValueError("invalid native metadata")
    return True


def _validate_keytab(raw: str, meta: dict, versions: frozenset[int]) -> bool:
    meta = validate_metadata(meta)
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 16384:
        raise ValueError("invalid native keytab")
    principals = {meta["hostname"].upper() + "$@" + meta["realm"].upper(),
                  f"host/{meta['hostname']}.{meta['realm']}@{meta['realm'].upper()}"}
    entries = set()
    lines = raw.splitlines()
    if not lines or lines.pop(0) != "Vno  Type                                        Principal":
        raise ValueError("invalid native keytab")
    types = {"AES-256 CTS mode with 96-bit SHA-1 HMAC": "aes256-cts-hmac-sha1-96",
             "AES-128 CTS mode with 96-bit SHA-1 HMAC": "aes128-cts-hmac-sha1-96",
             "ArcFour with HMAC/md5": "DEPRECATED:arcfour-hmac"}
    for line in lines:
        match = re.fullmatch(r"\s*(-?[0-9]+)  (.+?) +([^\s]+)", line)
        if match is None:
            raise ValueError("invalid native keytab")
        entry = (int(match[1]), match[3], types.get(match[2]))
        if (entry in entries or entry[0] not in versions or entry[1] not in principals
                or entry[2] not in _AES | {"DEPRECATED:arcfour-hmac"}):
            raise ValueError("invalid native keytab")
        entries.add(entry)
    if any((version, principal, kind) not in entries for version in versions
           for principal in principals for kind in _AES):
        raise ValueError("invalid native keytab")
    return True


def validate_rehearsal_keytab(raw: str, meta: dict) -> bool:
    # Some native versions emit the current placeholder only, others also the
    # previous password placeholder.  Neither proves a real directory KVNO.
    versions = frozenset((-1, -2)) if re.search(r"^\s*-2\s", raw, re.M) else frozenset((-1,))
    return _validate_keytab(raw, meta, versions)


def validate_domain_keytab(raw: str, meta: dict, kvno: int) -> bool:
    if type(kvno) is not int or not 1 <= kvno <= 0xffffffff:
        raise ValueError("invalid directory key version")
    return _validate_keytab(raw, meta, frozenset((kvno,)))
