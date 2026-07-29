package helper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	executionControllerURL       = "https://192.168.100.17:18092"
	executionRelayAddress        = "127.0.0.1:18192"
	executionRelayPort           = 18192
	maxExecutionManifestBytes    = 1 << 20
	maxExecutionSignatureBytes   = 16 << 10
	maxExecutionArtifactBytes    = 64 << 20
	executionRequestTimeout      = 30 * time.Second
	executionTLSHandshakeTimeout = 5 * time.Second
)

var (
	executionArtifactNames = []string{
		"autoinstall.scm",
		"vm-profile.scm",
		"pkg-groups.tar",
		"install-scripts.tar",
	}
	executionBundleNames = []string{
		"execution-manifest.json",
		"execution-manifest-signature.json",
		"autoinstall.scm",
		"vm-profile.scm",
		"pkg-groups.tar",
		"install-scripts.tar",
	}
	executionSessionPattern = regexp.MustCompile(
		`^install-\d{8}T\d{6}Z-[0-9a-f]{8}$`,
	)
	executionManifestPathPattern = regexp.MustCompile(
		`^/v2/install-sessions/(install-\d{8}T\d{6}Z-[0-9a-f]{8})/execution/manifest$`,
	)
	executionIdentifierPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`,
	)
)

type DownloadExecutionBundleInput struct {
	ManifestURL   string
	Destination   string
	CACertificate []byte
	Credential    string
}

type DownloadExecutionBundleResult struct {
	SessionID string
}

type VerifyExecutionBundleInput struct {
	ManifestPath string
	Plan         []byte
	Inventory    []byte
	PublicKey    []byte
	SessionID    string
	Now          time.Time
}

type ExecutionBundleVerification struct {
	SessionID       string
	PlanSHA256      string
	InventorySHA256 string
	TargetDisk      string
	DiskFingerprint string
	ExpiresAt       time.Time
}

type executionArtifactMetadata struct {
	SHA256    string
	SizeBytes int64
}

type executionManifest struct {
	SessionID       string
	PlanSHA256      string
	InventorySHA256 string
	ProfileID       string
	ProfileVersion  int64
	ISOID           string
	ISOSHA256       string
	TargetDisk      string
	DiskFingerprint string
	AuthorizedAt    time.Time
	ExpiresAt       time.Time
	Artifacts       map[string]executionArtifactMetadata
}

type executionManifestSignature struct {
	KeyID          string
	ManifestSHA256 string
	Signature      []byte
}

type executionDownload struct {
	path  string
	name  string
	limit int64
}

type ServeExecutionMetadataInput struct {
	Directory string
	Port      int
	Deadline  time.Time
}

func DownloadExecutionBundle(
	ctx context.Context,
	input DownloadExecutionBundleInput,
) (DownloadExecutionBundleResult, error) {
	return downloadExecutionBundleWithPolicy(ctx, input, true)
}

func downloadExecutionBundle(
	ctx context.Context,
	input DownloadExecutionBundleInput,
) error {
	_, err := downloadExecutionBundleWithPolicy(ctx, input, false)
	return err
}

func downloadExecutionBundleWithPolicy(
	ctx context.Context,
	input DownloadExecutionBundleInput,
	requireFixedController bool,
) (DownloadExecutionBundleResult, error) {
	manifestURL, sessionID, err := parseExecutionManifestURL(
		input.ManifestURL, requireFixedController,
	)
	if err != nil {
		return DownloadExecutionBundleResult{}, err
	}
	if !executionSessionPattern.MatchString(sessionID) ||
		!regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(input.Credential) {
		return DownloadExecutionBundleResult{}, contractError(
			"execution_download_invalid",
			"execution download binding is invalid",
		)
	}
	if len(input.CACertificate) == 0 ||
		len(input.CACertificate) > maxExecutionManifestBytes {
		return DownloadExecutionBundleResult{}, contractError(
			"execution_ca_invalid",
			"execution CA certificate is invalid",
		)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(input.CACertificate) {
		return DownloadExecutionBundleResult{}, contractError(
			"execution_ca_invalid",
			"execution CA certificate is invalid",
		)
	}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
		},
		DisableCompression:    true,
		TLSHandshakeTimeout:   executionTLSHandshakeTimeout,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   executionRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	rootPath := strings.TrimSuffix(manifestURL.Path, "/manifest")
	downloads := []executionDownload{
		{
			path:  rootPath + "/manifest",
			name:  "execution-manifest.json",
			limit: maxExecutionManifestBytes,
		},
		{
			path:  rootPath + "/manifest-signature",
			name:  "execution-manifest-signature.json",
			limit: maxExecutionSignatureBytes,
		},
	}
	for _, name := range executionArtifactNames {
		downloads = append(downloads, executionDownload{
			path:  rootPath + "/artifacts/" + name,
			name:  name,
			limit: maxExecutionArtifactBytes,
		})
	}
	if !filepath.IsAbs(input.Destination) ||
		filepath.Base(input.Destination) == "." ||
		filepath.Base(input.Destination) == string(filepath.Separator) {
		return DownloadExecutionBundleResult{}, contractError(
			"execution_destination_unsafe",
			"execution destination is unsafe",
		)
	}
	parent := filepath.Dir(input.Destination)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return DownloadExecutionBundleResult{}, contractError(
			"execution_destination_unsafe",
			"execution destination parent is unsafe",
		)
	}
	if _, err := os.Lstat(input.Destination); !os.IsNotExist(err) {
		return DownloadExecutionBundleResult{}, contractError(
			"execution_destination_unsafe",
			"execution destination already exists",
		)
	}
	temporary, err := os.MkdirTemp(
		parent, "."+filepath.Base(input.Destination)+".tmp-*",
	)
	if err != nil {
		return DownloadExecutionBundleResult{}, contractError(
			"execution_download_failed",
			"cannot create execution bundle staging directory",
		)
	}
	committed := false
	defer func() {
		if !committed {
			cleanupExecutionBundle(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return DownloadExecutionBundleResult{}, contractError(
			"execution_download_failed",
			"cannot protect execution bundle staging directory",
		)
	}
	for _, item := range downloads {
		requestURL := *manifestURL
		requestURL.Path = item.path
		requestURL.RawPath = ""
		requestURL.RawQuery = ""
		requestURL.ForceQuery = false
		requestURL.Fragment = ""
		raw, err := fetchExecutionFile(
			ctx, client, requestURL.String(), input.Credential, item.limit,
		)
		if err != nil {
			return DownloadExecutionBundleResult{}, err
		}
		if err := writeExclusiveExecutionFile(
			filepath.Join(temporary, item.name), raw,
		); err != nil {
			return DownloadExecutionBundleResult{}, err
		}
	}
	if err := os.Rename(temporary, input.Destination); err != nil {
		return DownloadExecutionBundleResult{}, contractError(
			"execution_download_failed",
			"cannot publish execution bundle",
		)
	}
	committed = true
	return DownloadExecutionBundleResult{SessionID: sessionID}, nil
}

func parseExecutionManifestURL(
	value string,
	requireFixedController bool,
) (*url.URL, string, error) {
	parsed, err := url.Parse(value)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery ||
		parsed.Fragment != "" {
		return nil, "", contractError(
			"execution_url_invalid",
			"execution manifest URL is invalid",
		)
	}
	if requireFixedController &&
		parsed.Scheme+"://"+parsed.Host != executionControllerURL {
		return nil, "", contractError(
			"execution_url_invalid",
			"execution manifest URL does not use the fixed controller",
		)
	}
	match := executionManifestPathPattern.FindStringSubmatch(parsed.Path)
	if len(match) != 2 {
		return nil, "", contractError(
			"execution_url_invalid",
			"execution manifest URL path is invalid",
		)
	}
	return parsed, match[1], nil
}

func fetchExecutionFile(
	ctx context.Context,
	client *http.Client,
	requestURL string,
	credential string,
	limit int64,
) ([]byte, error) {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, requestURL, nil,
	)
	if err != nil {
		return nil, contractError(
			"execution_download_failed",
			"cannot create execution download request",
		)
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return nil, contractError(
			"execution_download_failed",
			"execution download failed",
		)
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, contractError(
			"execution_redirect_rejected",
			"execution download redirect is rejected",
		)
	}
	if response.StatusCode != http.StatusOK {
		return nil, contractError(
			"execution_download_rejected",
			"execution download was rejected",
		)
	}
	if response.Header.Get("Cache-Control") != "no-store" ||
		response.ContentLength < 1 ||
		response.ContentLength > limit {
		return nil, contractError(
			"execution_response_invalid",
			"execution response metadata is invalid",
		)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil ||
		int64(len(raw)) != response.ContentLength ||
		int64(len(raw)) > limit {
		return nil, contractError(
			"execution_response_invalid",
			"execution response body is invalid",
		)
	}
	return raw, nil
}

func writeExclusiveExecutionFile(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return contractError(
			"execution_download_failed",
			"cannot create execution bundle file",
		)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return contractError(
			"execution_download_failed",
			"cannot protect execution bundle file",
		)
	}
	if _, err := file.Write(raw); err != nil {
		return contractError(
			"execution_download_failed",
			"cannot write execution bundle file",
		)
	}
	if err := file.Sync(); err != nil {
		return contractError(
			"execution_download_failed",
			"cannot sync execution bundle file",
		)
	}
	if err := file.Close(); err != nil {
		return contractError(
			"execution_download_failed",
			"cannot close execution bundle file",
		)
	}
	complete = true
	return nil
}

func VerifyExecutionBundle(
	input VerifyExecutionBundleInput,
) (ExecutionBundleVerification, error) {
	if !executionSessionPattern.MatchString(input.SessionID) ||
		input.Now.IsZero() {
		return ExecutionBundleVerification{}, contractError(
			"execution_binding_invalid",
			"execution verification binding is invalid",
		)
	}
	directory := filepath.Dir(input.ManifestPath)
	if filepath.Base(input.ManifestPath) != "execution-manifest.json" {
		return ExecutionBundleVerification{}, contractError(
			"execution_manifest_invalid",
			"execution manifest path is invalid",
		)
	}
	if err := requireExactExecutionBundle(directory); err != nil {
		return ExecutionBundleVerification{}, err
	}
	manifestRaw, err := readExecutionFile(
		input.ManifestPath, maxExecutionManifestBytes,
	)
	if err != nil {
		return ExecutionBundleVerification{}, err
	}
	manifest, err := parseExecutionManifest(manifestRaw)
	if err != nil {
		return ExecutionBundleVerification{}, err
	}
	signatureRaw, err := readExecutionFile(
		filepath.Join(directory, "execution-manifest-signature.json"),
		maxExecutionSignatureBytes,
	)
	if err != nil {
		return ExecutionBundleVerification{}, err
	}
	signature, err := parseExecutionManifestSignature(signatureRaw)
	if err != nil {
		return ExecutionBundleVerification{}, err
	}
	publicKey, err := parsePublicKey(input.PublicKey)
	if err != nil {
		return ExecutionBundleVerification{}, err
	}
	manifestDigest := sha256.Sum256(manifestRaw)
	manifestHash := hex.EncodeToString(manifestDigest[:])
	if signature.KeyID != publicKey.KeyID ||
		signature.ManifestSHA256 != manifestHash ||
		!ed25519.Verify(
			publicKey.PublicKey, manifestRaw, signature.Signature,
		) {
		return ExecutionBundleVerification{}, contractError(
			"execution_signature_invalid",
			"execution manifest signature is invalid",
		)
	}
	plan, err := exactCanonicalPlan(input.Plan)
	if err != nil {
		return ExecutionBundleVerification{}, err
	}
	inventory, err := ParseInventory(input.Inventory)
	if err != nil {
		return ExecutionBundleVerification{}, err
	}
	canonicalInventory, err := canonicalJSON(inventoryMap(inventory))
	if err != nil {
		return ExecutionBundleVerification{}, err
	}
	inventoryDigest := sha256.Sum256(canonicalInventory)
	inventoryHash := hex.EncodeToString(inventoryDigest[:])
	planDigest := sha256.Sum256(input.Plan)
	planHash := hex.EncodeToString(planDigest[:])
	selected, _, err := matchPlanInventory(plan, inventory)
	if err != nil {
		return ExecutionBundleVerification{}, err
	}
	if manifest.SessionID != input.SessionID ||
		plan.SessionID != input.SessionID ||
		manifest.PlanSHA256 != planHash ||
		manifest.InventorySHA256 != inventoryHash ||
		plan.InventorySHA256 != inventoryHash ||
		manifest.TargetDisk != plan.TargetDisk.Path ||
		manifest.DiskFingerprint != plan.TargetDisk.Fingerprint ||
		DiskFingerprint(selected) != plan.TargetDisk.Fingerprint ||
		manifest.ProfileID != plan.ProfileID ||
		manifest.ProfileVersion != plan.ProfileVersion ||
		manifest.ISOID != plan.ISOID ||
		manifest.ISOSHA256 != plan.ISOSHA256 {
		return ExecutionBundleVerification{}, contractError(
			"execution_binding_mismatch",
			"execution manifest binding differs",
		)
	}
	if !input.Now.Before(manifest.ExpiresAt) {
		return ExecutionBundleVerification{}, contractError(
			"execution_expired",
			"execution authorization is expired",
		)
	}
	for _, name := range executionArtifactNames {
		metadata := manifest.Artifacts[name]
		raw, err := readExecutionFile(
			filepath.Join(directory, name), maxExecutionArtifactBytes,
		)
		if err != nil {
			return ExecutionBundleVerification{}, err
		}
		digest := sha256.Sum256(raw)
		if int64(len(raw)) != metadata.SizeBytes ||
			hex.EncodeToString(digest[:]) != metadata.SHA256 {
			return ExecutionBundleVerification{}, contractError(
				"execution_artifact_mismatch",
				"execution artifact binding differs",
			)
		}
	}
	return ExecutionBundleVerification{
		SessionID: input.SessionID, PlanSHA256: planHash,
		InventorySHA256: inventoryHash,
		TargetDisk:      plan.TargetDisk.Path,
		DiskFingerprint: plan.TargetDisk.Fingerprint,
		ExpiresAt:       manifest.ExpiresAt,
	}, nil
}

func parseExecutionManifest(raw []byte) (executionManifest, error) {
	value, err := parseExactCanonicalExecutionJSON(
		raw, maxExecutionManifestBytes, "execution_manifest_invalid",
	)
	if err != nil {
		return executionManifest{}, err
	}
	root, err := objectValue(value, "execution_manifest")
	if err != nil {
		return executionManifest{}, err
	}
	if err := requireFields(root, []string{
		"schema_version", "session_id", "plan_sha256",
		"inventory_sha256", "profile_id", "profile_version",
		"iso_id", "iso_sha256", "target_disk", "authorized_at",
		"expires_at", "artifacts",
	}, "execution_manifest"); err != nil {
		return executionManifest{}, err
	}
	version, err := positiveIntegerValue(
		root["schema_version"], "execution_manifest",
	)
	if err != nil || version != 1 {
		return executionManifest{}, contractError(
			"execution_manifest_invalid",
			"execution manifest schema is invalid",
		)
	}
	values := make(map[string]string, 8)
	for _, name := range []string{
		"session_id", "plan_sha256", "inventory_sha256",
		"profile_id", "iso_id", "iso_sha256",
		"authorized_at", "expires_at",
	} {
		value, err := stringValue(root[name], "execution_manifest")
		if err != nil {
			return executionManifest{}, err
		}
		values[name] = value
	}
	if !executionSessionPattern.MatchString(values["session_id"]) ||
		!sha256Pattern.MatchString(values["plan_sha256"]) ||
		!sha256Pattern.MatchString(values["inventory_sha256"]) ||
		!sha256Pattern.MatchString(values["iso_sha256"]) ||
		!executionIdentifierPattern.MatchString(values["profile_id"]) ||
		!executionIdentifierPattern.MatchString(values["iso_id"]) {
		return executionManifest{}, contractError(
			"execution_manifest_invalid",
			"execution manifest binding is invalid",
		)
	}
	profileVersion, err := positiveIntegerValue(
		root["profile_version"], "execution_manifest",
	)
	if err != nil {
		return executionManifest{}, err
	}
	target, err := objectValue(
		root["target_disk"], "execution_manifest_target",
	)
	if err != nil {
		return executionManifest{}, err
	}
	if err := requireFields(
		target, []string{"path", "fingerprint"},
		"execution_manifest_target",
	); err != nil {
		return executionManifest{}, err
	}
	targetPath, err := stringValue(
		target["path"], "execution_manifest_target",
	)
	if err != nil || !diskPathPattern.MatchString(targetPath) {
		return executionManifest{}, contractError(
			"execution_manifest_invalid",
			"execution manifest target path is invalid",
		)
	}
	fingerprint, err := stringValue(
		target["fingerprint"], "execution_manifest_target",
	)
	if err != nil ||
		!regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(fingerprint) {
		return executionManifest{}, contractError(
			"execution_manifest_invalid",
			"execution manifest target fingerprint is invalid",
		)
	}
	authorizedAt, err := time.Parse(time.RFC3339, values["authorized_at"])
	if err != nil ||
		canonicalExecutionTimestamp(authorizedAt) != values["authorized_at"] {
		return executionManifest{}, contractError(
			"execution_manifest_invalid",
			"execution manifest authorization time is invalid",
		)
	}
	expiresAt, err := time.Parse(time.RFC3339, values["expires_at"])
	if err != nil ||
		canonicalExecutionTimestamp(expiresAt) != values["expires_at"] ||
		!expiresAt.After(authorizedAt) {
		return executionManifest{}, contractError(
			"execution_manifest_invalid",
			"execution manifest expiry is invalid",
		)
	}
	artifactObject, err := objectValue(
		root["artifacts"], "execution_manifest_artifacts",
	)
	if err != nil {
		return executionManifest{}, err
	}
	if err := requireFields(
		artifactObject, executionArtifactNames,
		"execution_manifest_artifacts",
	); err != nil {
		return executionManifest{}, err
	}
	artifacts := make(map[string]executionArtifactMetadata, len(executionArtifactNames))
	for _, name := range executionArtifactNames {
		metadata, err := objectValue(
			artifactObject[name], "execution_manifest_artifact",
		)
		if err != nil {
			return executionManifest{}, err
		}
		if err := requireFields(
			metadata, []string{"sha256", "size_bytes"},
			"execution_manifest_artifact",
		); err != nil {
			return executionManifest{}, err
		}
		digest, err := stringValue(
			metadata["sha256"], "execution_manifest_artifact",
		)
		if err != nil || !sha256Pattern.MatchString(digest) {
			return executionManifest{}, contractError(
				"execution_manifest_invalid",
				"execution artifact digest is invalid",
			)
		}
		size, err := positiveIntegerValue(
			metadata["size_bytes"], "execution_manifest_artifact",
		)
		if err != nil || size > maxExecutionArtifactBytes {
			return executionManifest{}, contractError(
				"execution_manifest_invalid",
				"execution artifact length is invalid",
			)
		}
		artifacts[name] = executionArtifactMetadata{
			SHA256: digest, SizeBytes: size,
		}
	}
	return executionManifest{
		SessionID:       values["session_id"],
		PlanSHA256:      values["plan_sha256"],
		InventorySHA256: values["inventory_sha256"],
		ProfileID:       values["profile_id"],
		ProfileVersion:  profileVersion,
		ISOID:           values["iso_id"],
		ISOSHA256:       values["iso_sha256"],
		TargetDisk:      targetPath,
		DiskFingerprint: fingerprint,
		AuthorizedAt:    authorizedAt,
		ExpiresAt:       expiresAt,
		Artifacts:       artifacts,
	}, nil
}

func canonicalExecutionTimestamp(value time.Time) string {
	return strings.TrimSuffix(
		value.UTC().Format(time.RFC3339Nano), "Z",
	) + "+00:00"
}

func parseExecutionManifestSignature(
	raw []byte,
) (executionManifestSignature, error) {
	value, err := parseExactCanonicalExecutionJSON(
		raw, maxExecutionSignatureBytes, "execution_signature_invalid",
	)
	if err != nil {
		return executionManifestSignature{}, err
	}
	root, err := objectValue(value, "execution_signature")
	if err != nil {
		return executionManifestSignature{}, err
	}
	if err := requireFields(root, []string{
		"schema_version", "algorithm", "key_id", "signed_file",
		"manifest_sha256", "signature_b64",
	}, "execution_signature"); err != nil {
		return executionManifestSignature{}, err
	}
	version, err := positiveIntegerValue(
		root["schema_version"], "execution_signature",
	)
	if err != nil || version != 1 {
		return executionManifestSignature{}, contractError(
			"execution_signature_invalid",
			"execution signature schema is invalid",
		)
	}
	values := make(map[string]string, 5)
	for _, name := range []string{
		"algorithm", "key_id", "signed_file",
		"manifest_sha256", "signature_b64",
	} {
		value, err := stringValue(root[name], "execution_signature")
		if err != nil {
			return executionManifestSignature{}, err
		}
		values[name] = value
	}
	if values["algorithm"] != "ed25519" ||
		values["signed_file"] != "execution-manifest.json" ||
		!regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(values["key_id"]) ||
		!sha256Pattern.MatchString(values["manifest_sha256"]) {
		return executionManifestSignature{}, contractError(
			"execution_signature_invalid",
			"execution signature metadata is invalid",
		)
	}
	signature, err := base64.StdEncoding.DecodeString(values["signature_b64"])
	if err != nil ||
		len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != values["signature_b64"] {
		return executionManifestSignature{}, contractError(
			"execution_signature_invalid",
			"execution signature value is invalid",
		)
	}
	return executionManifestSignature{
		KeyID:          values["key_id"],
		ManifestSHA256: values["manifest_sha256"],
		Signature:      signature,
	}, nil
}

func parseExactCanonicalExecutionJSON(
	raw []byte,
	limit int,
	code string,
) (any, error) {
	if len(raw) < 2 || len(raw) > limit || raw[len(raw)-1] != '\n' {
		return nil, contractError(code, "execution JSON bytes are invalid")
	}
	value, err := parseStrictJSON(raw)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicalJSON(value)
	if err != nil {
		return nil, contractError(code, "execution JSON is invalid")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return nil, contractError(code, "execution JSON is not canonical")
	}
	return value, nil
}

func requireExactExecutionBundle(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return contractError(
			"execution_bundle_invalid",
			"execution bundle directory is invalid",
		)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(executionBundleNames) {
		return contractError(
			"execution_bundle_invalid",
			"execution bundle file set is invalid",
		)
	}
	expected := make(map[string]struct{}, len(executionBundleNames))
	for _, name := range executionBundleNames {
		expected[name] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok ||
			entry.Type()&os.ModeSymlink != 0 {
			return contractError(
				"execution_bundle_invalid",
				"execution bundle file set is invalid",
			)
		}
	}
	return nil
}

func readExecutionFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Size() < 1 ||
		info.Size() > maximum {
		return nil, contractError(
			"execution_file_invalid",
			"execution bundle file is invalid",
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, contractError(
			"execution_file_invalid",
			"cannot open execution bundle file",
		)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil ||
		int64(len(raw)) != info.Size() ||
		int64(len(raw)) > maximum {
		return nil, contractError(
			"execution_file_invalid",
			"cannot read execution bundle file",
		)
	}
	after, err := file.Stat()
	if err != nil ||
		!after.Mode().IsRegular() ||
		!os.SameFile(info, after) ||
		after.Size() != info.Size() {
		return nil, contractError(
			"execution_file_invalid",
			"execution bundle file changed while reading",
		)
	}
	return raw, nil
}

func loadExecutionArtifacts(directory string) (map[string][]byte, error) {
	if err := requireExactExecutionBundle(directory); err != nil {
		return nil, err
	}
	manifestRaw, err := readExecutionFile(
		filepath.Join(directory, "execution-manifest.json"),
		maxExecutionManifestBytes,
	)
	if err != nil {
		return nil, err
	}
	manifest, err := parseExecutionManifest(manifestRaw)
	if err != nil {
		return nil, err
	}
	artifacts := make(map[string][]byte, len(executionArtifactNames))
	for _, name := range executionArtifactNames {
		raw, err := readExecutionFile(
			filepath.Join(directory, name), maxExecutionArtifactBytes,
		)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(raw)
		metadata := manifest.Artifacts[name]
		if int64(len(raw)) != metadata.SizeBytes ||
			hex.EncodeToString(digest[:]) != metadata.SHA256 {
			return nil, contractError(
				"execution_artifact_mismatch",
				"execution artifact binding differs",
			)
		}
		artifacts[name] = raw
	}
	return artifacts, nil
}

type executionMetadataHandler struct {
	artifacts    map[string][]byte
	served       map[string]bool
	mutex        sync.Mutex
	complete     func()
	completeOnce sync.Once
}

func newExecutionMetadataHandler(
	directory string,
	complete func(),
) http.Handler {
	artifacts, err := loadExecutionArtifacts(directory)
	if err != nil {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			writeRelayError(response, request, http.StatusServiceUnavailable)
		})
	}
	return &executionMetadataHandler{
		artifacts: artifacts,
		served:    make(map[string]bool, len(artifacts)),
		complete:  complete,
	}
}

func (handler *executionMetadataHandler) ServeHTTP(
	response http.ResponseWriter,
	request *http.Request,
) {
	path := request.URL.Path
	if request.RequestURI != path {
		writeRelayError(response, request, http.StatusNotFound)
		return
	}
	name := strings.TrimPrefix(path, "/")
	content, exists := handler.artifacts[name]
	if path != "/"+name || !exists {
		writeRelayError(response, request, http.StatusNotFound)
		return
	}
	if request.Method != http.MethodGet &&
		request.Method != http.MethodHead {
		writeRelayError(response, request, http.StatusMethodNotAllowed)
		return
	}
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Length", strconv.Itoa(len(content)))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodHead {
		return
	}
	written, err := response.Write(content)
	if err != nil || written != len(content) {
		return
	}
	handler.mutex.Lock()
	handler.served[name] = true
	allServed := len(handler.served) == len(handler.artifacts)
	handler.mutex.Unlock()
	if allServed {
		handler.completeOnce.Do(func() {
			go handler.complete()
		})
	}
}

func writeRelayError(
	response http.ResponseWriter,
	request *http.Request,
	status int,
) {
	body := []byte(http.StatusText(status) + "\n")
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = response.Write(body)
	}
}

func ServeExecutionMetadata(
	ctx context.Context,
	input ServeExecutionMetadataInput,
) error {
	if input.Port != executionRelayPort ||
		input.Deadline.IsZero() ||
		!time.Now().Before(input.Deadline) {
		return contractError(
			"execution_relay_invalid",
			"execution relay binding is invalid",
		)
	}
	artifacts, err := loadExecutionArtifacts(input.Directory)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", executionRelayAddress)
	if err != nil {
		return contractError(
			"execution_relay_bind_failed",
			"cannot bind execution metadata relay",
		)
	}
	defer listener.Close()
	defer cleanupExecutionBundle(input.Directory)
	completed := make(chan struct{}, 1)
	handler := &executionMetadataHandler{
		artifacts: artifacts,
		served:    make(map[string]bool, len(artifacts)),
		complete: func() {
			select {
			case completed <- struct{}{}:
			default:
			}
		},
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	served := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		served <- err
	}()
	timer := time.NewTimer(time.Until(input.Deadline))
	defer timer.Stop()
	select {
	case err := <-served:
		if err != nil {
			return contractError(
				"execution_relay_failed",
				"execution metadata relay failed",
			)
		}
		return nil
	case <-completed:
	case <-timer.C:
	case <-ctx.Done():
	}
	shutdownContext, cancel := context.WithTimeout(
		context.Background(), 2*time.Second,
	)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		return contractError(
			"execution_relay_failed",
			"execution metadata relay shutdown failed",
		)
	}
	if err := <-served; err != nil {
		return contractError(
			"execution_relay_failed",
			"execution metadata relay failed",
		)
	}
	return nil
}

func cleanupExecutionBundle(directory string) {
	for _, name := range executionBundleNames {
		_ = os.Remove(filepath.Join(directory, name))
	}
	_ = os.Remove(directory)
}

func executionManifestURL(sessionID string) string {
	return fmt.Sprintf(
		"%s/v2/install-sessions/%s/execution/manifest",
		executionControllerURL, sessionID,
	)
}
