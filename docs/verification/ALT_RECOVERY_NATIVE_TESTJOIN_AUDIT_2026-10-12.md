# Native Samba testjoin preparation audit

Status: source and read-only parser preparation, not live acceptance. No recovery write,
credential import or native testjoin was executed for this audit.

## Exact package and source provenance

Read-only RPM inspection of the selected disposable target reported
`samba-common` and `samba-client` version `4.21.9-alt4.p11.1`, source package
`samba-4.21.9-alt4.p11.1.src.rpm`. `/usr/bin/net` belongs to
`samba-common-tools-4.21.9-alt4.p11.1.x86_64`.

The official [ALT package repository](https://git.altlinux.org/people/usoltsevpv/packages/samba.git)
has release tag `4.21.9-alt4.p11.1`, tag object
`2cf47d08559d2a3f4840b993cdbf56e13ddbf6e1`, packaging commit
`5dd1c18386d33a4b51ea060c83f111a2c9433984`. Its `.gear/rules` builds upstream
`samba-4.21.9` plus the diff to `v4.21.9-alt4`; `.gear/tags/list` identifies
the latter source commit as `532170350db04e6b9b96943c6ecac92a8c4ae0d2`.
`samba4.spec` applies that generated patch and `extra/samba-grouppwd.patch`.
The latter changes only the winbind group password placeholder.
The source RPM has not been downloaded/extracted or its signature verified;
this is an exact packaging/source-tag inspection, not a reproducible binary
build attestation.

Seven relevant files were read from that ALT source commit and compared byte
for byte to the [upstream 4.21.9 release](https://github.com/samba-team/samba/tree/samba-4.21.9):

| Source file | Comparison |
| --- | --- |
| `source3/utils/net_ads.c` | Identical |
| `source3/libads/ads_struct.c` | Identical |
| `source3/utils/net_util.c` | Identical |
| `source3/passdb/secrets.c` | Identical |
| `source3/passdb/machine_account_secrets.c` | Identical |
| `source3/libads/sasl.c` | Identical |
| `source3/libads/ldap.c` | One change in `ads_create_machine_acct`, outside the observed testjoin path |

The LDAP change additionally requires a positive result count before choosing
the existing-account password-change branch. It does not modify the inspected
connection/fallback path. ALT `ldap.c` SHA-256 is
`8571bed590d1b52faba76710e6220320459a559adccc2d337f5af53878287cf0`;
shared `net_ads.c` SHA-256 is
`9e51ab799b2a84da9957cd6ef72afb9054e688b590bfb4668bd89bf0216d506f`.

## Observed native behavior and its meaning

`net_ads_testjoin` calls `net_ads_join_ok`, which loads machine credentials,
calls `get_dc_name` and runs `ads_startup(c, true, ...)`. Success reports an
ADS connection/authentication result; it does not independently return the
computer GUID/SID, OU or password version.

`ads_startup_int` passes the selected hostname to `ads_init`, but the inspected
initializer does not set `server.no_fallback`. `ads_connect_internal` can fall
through to `ads_find_dc` if contacting that hostname fails. The native IP
option alone does not establish an enforced peer for this ADS path. Native
site/affinity/name discovery can also update local caches.

`secrets_init_path` opens `secrets.tdb` with `O_RDWR|O_CREAT`. The credential
loader `cli_credentials_set_machine_account_db_ctx` reads legacy machine
password records and can consult the private secrets LDB. A future worker must
give Samba only a private scratch copy; no writable live database, host IPC
socket or inherited ticket cache may be accessible. Potential write-on-read
or database initialization must remain confined to scratch.

Native `create_local_private_krb5_conf_for_domain` writes under the Samba lock
directory and may include system Kerberos configuration. The future sandbox
must redirect private/state/cache/lock/log paths, explicitly control Kerberos
inputs and keep this native environment separate from the existing independent
pinned Kerberos proof. Fixed config must disable keytab synchronization and
password synchronization scripts and contain no includes or operator hooks.

The inspected upper call path invokes authentication, not explicit account,
password, SPN or DNS modification operations. This is not yet a complete
transitive proof for every credential/GENSEC/LDB/referral path. Normal server
authentication audit/accounting effects are not claimed absent.

Read-only native parser probes on the selected target fed synthetic
`EXAMPLE.INVALID` configuration through stdin to `testparm --suppress-prompt
--parameter-name=... /dev/stdin`. All five requested values were returned:
keytab sync `disabled`, empty password sync script, `create krb5 conf=No`,
`include system krb5 conf=No`, and SASL wrapping `seal`. The first candidate
returned rc 1 because its future `/work` directories did not exist and its
idmap range was unspecified; printed values alone were not accepted as PASS.
A second parser-only candidate used existing `/tmp` directory paths and an
explicit synthetic idmap range. All five probes then returned rc 0 with exact
expected values. No configuration file, credential or directory was created;
no native testjoin was invoked. This checks installed parser support only,
not future sandbox isolation or authentication behavior.

## Reviewed scope decision and next implementation

Independent review confirmed the fallback and scratch-write observations.
A second scope review confirmed that requiring network enforcement for native
testjoin was an additional restriction, not an original L4 requirement.
No host firewall, routing, network policy or new peer-enforcement component is
needed for this preparation step. Preserve these distinct checks:

- Independent Kerberos authentication and fresh GUID/SID/OU/KVNO continuity use
  the approved pinned DC and remain mandatory.
- Native Samba check records `native_testjoin_succeeded` and
  `native_testjoin_peer_pinning_unverified`. It is not a replacement for the
  pinned identity/credential checks.
- NSS records `selected_employee_resolved`; cached lookup is possible and is
  not graphical login or fresh employee-password authentication.

Before implementing the bounded online worker, finish the exact-package
credential/GENSEC/LDB path review, validate fixed config and all redirected
scratch paths with the actual native parser, and add negative tests preventing
live secret/keytab/config/IPC exposure. Bind startup InvocationID/PID with zero
restarts, retained temporary-policy bytes, imported artifact hashes and genuine
post-write context before and after the one native command. Remove scratch
credentials/caches before writing a durable verified receipt. No retry or
automatic policy restoration follows an entered failure.

After online proof, original-service restoration, explicit temporary-policy
handoff and additive Setup continuation are still required. None of this audit
authorizes a real machine-password reset or service action.
