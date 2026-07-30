#!/bin/bash
set -Eeuo pipefail

readonly v1_controller_url='http://192.168.100.17:18090'
readonly v2_controller_url='https://192.168.100.17:18092'
readonly source_sha256='2529f98bca03a652709434a6a17cd4aac5df20c0793927abdf784e8f9388243a'

die() { printf 'alt-install-release: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage: build-managed-iso-release.sh --source-commit <40-hex> --source-iso <ISO> --public-key <JSON> --release-id <ID> --iso-dir <DIR> --go <GO> [--agent-version agent-v1|agent-v2] [--execution-ca <PEM>]' >&2
    exit 2
}

source_commit= source_iso= public_key= release_id= iso_dir= go=
agent_version=agent-v1
execution_ca=
while (($#)); do
    case "$1" in
        --source-commit|--source-iso|--public-key|--release-id|--iso-dir|--go|--agent-version|--execution-ca)
            (($# >= 2)) || usage
            case "$1" in
                --source-commit) source_commit=$2 ;;
                --source-iso) source_iso=$2 ;;
                --public-key) public_key=$2 ;;
                --release-id) release_id=$2 ;;
                --iso-dir) iso_dir=$2 ;;
                --go) go=$2 ;;
                --agent-version) agent_version=$2 ;;
                --execution-ca) execution_ca=$2 ;;
            esac
            shift 2 ;;
        *) usage ;;
    esac
done
[[ -n "$source_commit" && -n "$source_iso" && -n "$public_key" && -n "$release_id" && -n "$iso_dir" && -n "$go" ]] || usage
case "$agent_version" in
    agent-v1)
        [[ -z "$execution_ca" ]] ||
            die 'Execution CA is valid only for agent-v2'
        ;;
    agent-v2)
        [[ -n "$execution_ca" ]] || usage
        ;;
    *) die 'Agent version is invalid' ;;
esac

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_root/../../.." && pwd -P)
contract="$script_root/lib/release-contract.py"
for command in awk bash chmod date flock git install mktemp mv python3 readlink rm sha256sum tar; do command -v "$command" >/dev/null || die "Missing required command: $command"; done
[[ -x "$go" && -f "$contract" && ! -L "$contract" ]] || die 'Release tooling is unreadable'
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || die 'Source commit is invalid'
[[ -f "$source_iso" && -r "$source_iso" && ! -L "$source_iso" ]] || die 'Source ISO is unreadable'
[[ -f "$public_key" && -r "$public_key" && ! -L "$public_key" ]] || die 'Public key is unreadable'
case "${public_key,,}" in *.pem|*.key|*credential*|*session*|*private*) die 'Public key path is unsafe' ;; esac
if [[ "$agent_version" == agent-v2 ]]; then
    [[ -f "$execution_ca" && -r "$execution_ca" &&
        ! -L "$execution_ca" ]] || die 'Execution CA is unreadable'
    case "${execution_ca,,}" in
        *.key|*credential*|*session*|*private*|*secret*)
            die 'Execution CA path is unsafe'
            ;;
    esac
fi
[[ -d "$iso_dir" && ! -L "$iso_dir" ]] || die 'ISO directory is invalid'
iso_dir=$(readlink -f -- "$iso_dir") || die 'Cannot resolve ISO directory'
source_iso=$(readlink -f -- "$source_iso") || die 'Cannot resolve source ISO'
public_key=$(readlink -f -- "$public_key") || die 'Cannot resolve public key'
if [[ "$agent_version" == agent-v2 ]]; then
    execution_ca=$(readlink -f -- "$execution_ca") ||
        die 'Cannot resolve execution CA'
fi
lock_file="$iso_dir/.alt-install-${agent_version}-release.lock"
exec {lock_fd}>"$lock_file"
flock -n "$lock_fd" || die 'Another managed ISO release is running'
[[ "$(sha256sum "$source_iso" | awk '{print $1}')" == "$source_sha256" ]] || die 'Source ISO identity mismatch'
python3 "$contract" validate-release-id --release-id "$release_id" || die 'Release ID is invalid'
resolved_commit=$(git -C "$repo_root" rev-parse --verify "${source_commit}^{commit}") || die 'Source commit is unavailable'
[[ "$resolved_commit" == "$source_commit" ]] || die 'Source commit is not canonical'

if [[ "$agent_version" == agent-v1 ]]; then
    output="$iso_dir/alt-kworkstation-11.4-agent-v1-$release_id.iso"
else
    output="$iso_dir/alt-kworkstation-11.4-agent-v2-$release_id.iso"
fi
sidecar="$output.build-manifest.json"
index=
if [[ "$agent_version" == agent-v1 ]]; then
    index="$iso_dir/alt-install-agent-v1-releases.json"
fi
[[ ! -e "$output" && ! -e "$sidecar" ]] || die 'Release output already exists'
stage=$(mktemp -d "$iso_dir/.alt-install-release-$release_id.XXXXXX")
chmod 0700 -- "$stage"
stage=$(readlink -f -- "$stage") || die 'Cannot resolve private release stage'
case "$stage" in "$iso_dir"/.alt-install-release-"$release_id".*) ;; *) die 'Release stage escaped ISO directory' ;; esac
cleanup() { case "$stage" in "$iso_dir"/.alt-install-release-"$release_id".*) rm -rf -- "$stage" ;; esac; }
trap cleanup EXIT

git -C "$repo_root" archive --format=tar "$source_commit" | tar -x -C "$stage"
checkout="$stage"
helper="$stage/alt-install-helper"
public_snapshot="$stage/controller-public-key.json"
install -m 0644 -- "$public_key" "$public_snapshot"
ca_snapshot=
if [[ "$agent_version" == agent-v2 ]]; then
    ca_snapshot="$stage/execution-ca.pem"
    install -m 0644 -- "$execution_ca" "$ca_snapshot"
fi
(
    cd "$checkout/deploy/alt-linux/install-agent/helper"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go" build -trimpath -buildvcs=false -ldflags='-buildid=' -o "$helper" ./cmd/alt-install-helper
)
staged_iso="$stage/release.iso"
if [[ "$agent_version" == agent-v1 ]]; then
    bash "$checkout/deploy/alt-linux/iso/agent-v1/build-managed-iso.sh" --source "$source_iso" --output "$staged_iso" --helper "$helper" --public-key "$public_snapshot" --build-id "release-$release_id" --controller-url "$v1_controller_url"
    bash "$checkout/deploy/alt-linux/iso/agent-v1/verify-managed-iso.sh" --iso "$staged_iso"
    created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    staged_index="$stage/releases.json"
    python3 "$contract" update-index --index "$index" --sidecar "$staged_iso.build-manifest.json" --release-id "$release_id" --commit "$source_commit" --created-at "$created_at" --output "$staged_index" || die 'Release index validation failed'
else
    bash "$checkout/deploy/alt-linux/iso/agent-v2/build-managed-iso.sh" --source "$source_iso" --output "$staged_iso" --helper "$helper" --public-key "$public_snapshot" --ca-certificate "$ca_snapshot" --build-id "release-$release_id" --controller-url "$v2_controller_url"
    bash "$checkout/deploy/alt-linux/iso/agent-v2/verify-managed-iso.sh" \
        --iso "$staged_iso" --source "$source_iso"
fi
if [[ "$agent_version" == agent-v1 ]]; then
    mv -n -- "$staged_iso" "$output"
    [[ -f "$output" && ! -e "$staged_iso" ]] ||
        die 'ISO publication failed'
    mv -n -- "$staged_iso.build-manifest.json" "$sidecar"
    [[ -f "$sidecar" &&
        ! -e "$staged_iso.build-manifest.json" ]] ||
        die 'Sidecar publication failed'
    mv -f -- "$staged_index" "$index"
    printf 'release_iso=%s\nrelease_index=%s\n' "$output" "$index"
else
    # shellcheck source=../iso/agent-v2/lib/publish.sh
    source "$checkout/deploy/alt-linux/iso/agent-v2/lib/publish.sh"
    publish_managed_iso \
        "$staged_iso" "$staged_iso.build-manifest.json" \
        "$output" "$sidecar" ||
        die 'V2 release transaction failed'
    printf 'release_iso=%s\nrelease_sidecar=%s\n' "$output" "$sidecar"
fi
