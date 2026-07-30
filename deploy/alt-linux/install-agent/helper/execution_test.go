package helper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type executionFixture struct {
	directory string
	plan      []byte
	inventory []byte
	publicKey []byte
	sessionID string
	deadline  time.Time
	artifacts map[string][]byte
}

func validExecutionFixture(t *testing.T) executionFixture {
	t.Helper()
	inventory, planRaw, _, _, _, sessionID := loadCommandVector(t)
	plan, err := exactCanonicalPlan(planRaw)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest := sha256.Sum256(public)
	keyID := "sha256:" + hex.EncodeToString(keyDigest[:])
	publicKey, err := canonicalJSON(map[string]any{
		"schema_version": int64(1),
		"algorithm":      "ed25519",
		"key_id":         keyID,
		"public_key_b64": base64.StdEncoding.EncodeToString(public),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := map[string][]byte{
		"autoinstall.scm":     []byte("(define target \"/dev/vda\")\n"),
		"vm-profile.scm":      []byte("(define profile \"workstation\")\n"),
		"pkg-groups.tar":      []byte("package-groups"),
		"install-scripts.tar": []byte("install-scripts"),
	}
	artifactMetadata := make(map[string]any, len(artifacts))
	for name, content := range artifacts {
		digest := sha256.Sum256(content)
		artifactMetadata[name] = map[string]any{
			"sha256":     hex.EncodeToString(digest[:]),
			"size_bytes": int64(len(content)),
		}
	}
	authorizedAt := time.Date(2026, 7, 27, 12, 30, 0, 0, time.UTC)
	deadline := authorizedAt.Add(5 * time.Minute)
	planDigest := sha256.Sum256(planRaw)
	manifest, err := canonicalJSON(map[string]any{
		"schema_version":   int64(1),
		"session_id":       sessionID,
		"plan_sha256":      hex.EncodeToString(planDigest[:]),
		"inventory_sha256": plan.InventorySHA256,
		"profile_id":       plan.ProfileID,
		"profile_version":  plan.ProfileVersion,
		"iso_id":           plan.ISOID,
		"iso_sha256":       plan.ISOSHA256,
		"target_disk": map[string]any{
			"path":        plan.TargetDisk.Path,
			"fingerprint": plan.TargetDisk.Fingerprint,
		},
		"authorized_at": canonicalExecutionTimestamp(authorizedAt),
		"expires_at":    canonicalExecutionTimestamp(deadline),
		"artifacts":     artifactMetadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest = append(manifest, '\n')
	manifestDigest := sha256.Sum256(manifest)
	signature, err := canonicalJSON(map[string]any{
		"schema_version":  int64(1),
		"algorithm":       "ed25519",
		"key_id":          keyID,
		"signed_file":     "execution-manifest.json",
		"manifest_sha256": hex.EncodeToString(manifestDigest[:]),
		"signature_b64":   base64.StdEncoding.EncodeToString(ed25519.Sign(private, manifest)),
	})
	if err != nil {
		t.Fatal(err)
	}
	signature = append(signature, '\n')
	directory := t.TempDir()
	files := map[string][]byte{
		"execution-manifest.json":           manifest,
		"execution-manifest-signature.json": signature,
	}
	for name, content := range artifacts {
		files[name] = content
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return executionFixture{
		directory: directory, plan: planRaw, inventory: inventory,
		publicKey: publicKey, sessionID: sessionID, deadline: deadline,
		artifacts: artifacts,
	}
}

func verifyFixture(t *testing.T, fixture executionFixture) ExecutionBundleVerification {
	t.Helper()
	result, err := VerifyExecutionBundle(VerifyExecutionBundleInput{
		ManifestPath: filepath.Join(fixture.directory, "execution-manifest.json"),
		Plan:         fixture.plan, Inventory: fixture.inventory, PublicKey: fixture.publicKey,
		SessionID: fixture.sessionID, Now: fixture.deadline.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestVerifyExecutionBundleAcceptsCanonicalSignedBindings(t *testing.T) {
	fixture := validExecutionFixture(t)
	result := verifyFixture(t, fixture)
	if result.SessionID != fixture.sessionID ||
		result.TargetDisk == "" ||
		!result.ExpiresAt.Equal(fixture.deadline) {
		t.Fatalf("unexpected verification result: %+v", result)
	}
}

func TestVerifyExecutionBundleCommandEmitsBoundedResult(t *testing.T) {
	fixture := validExecutionFixture(t)
	paths := writeCommandInputs(t, t.TempDir(), map[string][]byte{
		"plan.json":       fixture.plan,
		"inventory.json":  fixture.inventory,
		"public-key.json": fixture.publicKey,
	})
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), []string{
		"verify-execution-bundle",
		"--manifest", filepath.Join(fixture.directory, "execution-manifest.json"),
		"--plan", paths["plan.json"],
		"--inventory", paths["inventory.json"],
		"--public-key", paths["public-key.json"],
		"--session", fixture.sessionID,
	}, &stdout, &stderr, commandDependencies{
		now: func() time.Time { return fixture.deadline.Add(-time.Minute) },
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	assertBoundedSuccessObject(
		t, stdout.Bytes(), "verify-execution-bundle",
	)
}

func TestVerifyExecutionBundleRejectsArtifactTamperingAndExtraFiles(t *testing.T) {
	for _, mutation := range []struct {
		name string
		run  func(t *testing.T, fixture executionFixture)
	}{
		{
			name: "tampered artifact",
			run: func(t *testing.T, fixture executionFixture) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(fixture.directory, "autoinstall.scm"),
					[]byte("tampered"), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unexpected file",
			run: func(t *testing.T, fixture executionFixture) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(fixture.directory, "status.json"),
					[]byte("{}"), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			fixture := validExecutionFixture(t)
			mutation.run(t, fixture)
			_, err := VerifyExecutionBundle(VerifyExecutionBundleInput{
				ManifestPath: filepath.Join(fixture.directory, "execution-manifest.json"),
				Plan:         fixture.plan, Inventory: fixture.inventory, PublicKey: fixture.publicKey,
				SessionID: fixture.sessionID, Now: fixture.deadline.Add(-time.Minute),
			})
			if err == nil {
				t.Fatal("verification accepted a mutated execution bundle")
			}
		})
	}
}

func TestVerifyExecutionBundleRejectsExpiredOrWrongPlanBinding(t *testing.T) {
	fixture := validExecutionFixture(t)
	for name, now := range map[string]time.Time{
		"at expiry":    fixture.deadline,
		"after expiry": fixture.deadline.Add(time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyExecutionBundle(VerifyExecutionBundleInput{
				ManifestPath: filepath.Join(fixture.directory, "execution-manifest.json"),
				Plan:         fixture.plan, Inventory: fixture.inventory, PublicKey: fixture.publicKey,
				SessionID: fixture.sessionID, Now: now,
			})
			if err == nil {
				t.Fatal("verification accepted an expired execution bundle")
			}
		})
	}
	changedPlan := append([]byte(nil), fixture.plan...)
	changedPlan[len(changedPlan)-1] ^= 1
	_, err := VerifyExecutionBundle(VerifyExecutionBundleInput{
		ManifestPath: filepath.Join(fixture.directory, "execution-manifest.json"),
		Plan:         changedPlan, Inventory: fixture.inventory, PublicKey: fixture.publicKey,
		SessionID: fixture.sessionID, Now: fixture.deadline.Add(-time.Minute),
	})
	if err == nil {
		t.Fatal("verification accepted a different plan")
	}
}

func TestDownloadExecutionBundleUsesExactRoutesAndBoundedBodies(t *testing.T) {
	fixture := validExecutionFixture(t)
	files := make(map[string][]byte)
	for _, name := range append([]string{
		"execution-manifest.json",
		"execution-manifest-signature.json",
	}, executionArtifactNames...) {
		raw, err := os.ReadFile(filepath.Join(fixture.directory, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = raw
	}
	var mu sync.Mutex
	var requested []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requested = append(requested, request.URL.RequestURI())
		mu.Unlock()
		if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("A", 43) {
			http.Error(response, "forbidden", http.StatusForbidden)
			return
		}
		root := "/v2/install-sessions/" + fixture.sessionID + "/execution"
		name := ""
		switch request.URL.Path {
		case root + "/manifest":
			name = "execution-manifest.json"
		case root + "/manifest-signature":
			name = "execution-manifest-signature.json"
		default:
			const prefix = "/artifacts/"
			index := strings.Index(request.URL.Path, prefix)
			if index >= 0 {
				name = request.URL.Path[index+len(prefix):]
			}
		}
		content, ok := files[name]
		if !ok || request.URL.RawQuery != "" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Length", fmt.Sprint(len(content)))
		_, _ = response.Write(content)
	}))
	defer server.Close()
	certificate := server.Certificate()
	ca := pemCertificate(t, certificate.Raw)
	destination := filepath.Join(t.TempDir(), "bundle")
	manifestURL := server.URL + "/v2/install-sessions/" + fixture.sessionID + "/execution/manifest"
	if err := downloadExecutionBundle(context.Background(), DownloadExecutionBundleInput{
		ManifestURL: manifestURL, Destination: destination, CACertificate: ca,
		Credential: strings.Repeat("A", 43),
	}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), requested...)
	mu.Unlock()
	want := []string{
		"/v2/install-sessions/" + fixture.sessionID + "/execution/manifest",
		"/v2/install-sessions/" + fixture.sessionID + "/execution/manifest-signature",
	}
	for _, name := range executionArtifactNames {
		want = append(want, "/v2/install-sessions/"+fixture.sessionID+"/execution/artifacts/"+name)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("routes differ:\ngot  %q\nwant %q", got, want)
	}
}

func TestDownloadExecutionBundleRejectsRedirectAndOversizedResponse(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "redirect",
			handler: func(response http.ResponseWriter, request *http.Request) {
				http.Redirect(response, request, "/elsewhere", http.StatusFound)
			},
		},
		{
			name: "oversized",
			handler: func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Length", fmt.Sprint(maxExecutionManifestBytes+1))
				response.WriteHeader(http.StatusOK)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewTLSServer(testCase.handler)
			defer server.Close()
			destination := filepath.Join(t.TempDir(), "bundle")
			err := downloadExecutionBundle(context.Background(), DownloadExecutionBundleInput{
				ManifestURL:   server.URL + "/v2/install-sessions/install-20260727T120000Z-a1b2c3d4/execution/manifest",
				Destination:   destination,
				CACertificate: pemCertificate(t, server.Certificate().Raw),
				Credential:    strings.Repeat("A", 43),
			})
			if err == nil {
				t.Fatal("unsafe response was accepted")
			}
			if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
				t.Fatalf("partial bundle remained: %v", statErr)
			}
		})
	}
}

func TestServeExecutionMetadataRejectsQueryTraversalAndMethods(t *testing.T) {
	fixture := validExecutionFixture(t)
	verifyFixture(t, fixture)
	server := httptest.NewServer(newExecutionMetadataHandler(
		fixture.directory, func() {},
	))
	defer server.Close()
	for _, testCase := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/autoinstall.scm?x=1", http.StatusNotFound},
		{http.MethodGet, "/../status.json", http.StatusNotFound},
		{http.MethodGet, "/%2e%2e%2fstatus.json", http.StatusNotFound},
		{http.MethodPost, "/autoinstall.scm", http.StatusMethodNotAllowed},
		{http.MethodGet, "/status.json", http.StatusNotFound},
	} {
		request, err := http.NewRequest(testCase.method, server.URL+testCase.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != testCase.status {
			t.Fatalf("%s %s = %d, want %d", testCase.method, testCase.path, response.StatusCode, testCase.status)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s omitted no-store", testCase.method, testCase.path)
		}
		if response.Header.Get("Location") != "" {
			t.Fatalf("%s %s redirected", testCase.method, testCase.path)
		}
	}
}

func TestServeExecutionMetadataCountsOnlySuccessfulGETs(t *testing.T) {
	fixture := validExecutionFixture(t)
	verifyFixture(t, fixture)
	completed := make(chan struct{}, 1)
	server := httptest.NewServer(newExecutionMetadataHandler(
		fixture.directory, func() { completed <- struct{}{} },
	))
	defer server.Close()
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		for _, name := range executionArtifactNames {
			request, err := http.NewRequest(method, server.URL+"/"+name, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatalf("%s %s failed: status=%d err=%v", method, name, response.StatusCode, err)
			}
			if response.Header.Get("Content-Length") != fmt.Sprint(len(fixture.artifacts[name])) {
				t.Fatalf("%s has wrong length", name)
			}
			if method == http.MethodHead && len(body) != 0 {
				t.Fatalf("HEAD %s returned a body", name)
			}
		}
		select {
		case <-completed:
			if method == http.MethodHead {
				t.Fatal("HEAD requests completed the one-time relay")
			}
		default:
			if method == http.MethodGet {
				t.Fatal("all successful GETs did not complete the relay")
			}
		}
	}
}

func TestServeExecutionMetadataSignalsReadinessAfterBind(t *testing.T) {
	fixture := validExecutionFixture(t)
	verifyFixture(t, fixture)
	readyFile := filepath.Join(t.TempDir(), "relay.ready")
	done := make(chan error, 1)
	go func() {
		done <- ServeExecutionMetadata(
			context.Background(),
			ServeExecutionMetadataInput{
				Directory: fixture.directory,
				Port:      executionRelayPort,
				Deadline:  time.Now().Add(time.Minute),
				ReadyFile: readyFile,
			},
		)
	}()
	waitForFileContent(
		t, readyFile, []byte("ALT_INSTALL_RELAY_READY_V1\n"),
	)
	client := &http.Client{Timeout: time.Second}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		for _, name := range executionArtifactNames {
			request, err := http.NewRequest(
				method,
				"http://"+executionRelayAddress+"/"+name,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf(
					"%s %s = %d",
					method, name, response.StatusCode,
				)
			}
		}
		if method == http.MethodHead {
			select {
			case err := <-done:
				t.Fatalf("HEAD ended relay: %v", err)
			default:
			}
		} else {
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for all GETs to stop relay")
			}
		}
	}
	if _, err := os.Lstat(readyFile); !os.IsNotExist(err) {
		t.Fatalf("readiness signal was not cleaned up: %v", err)
	}
}

func waitForFileContent(
	t *testing.T,
	path string,
	expected []byte,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			if !bytes.Equal(raw, expected) {
				t.Fatalf("readiness signal = %q", raw)
			}
			return
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if !time.Now().Before(deadline) {
			t.Fatal("timed out waiting for relay readiness signal")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func pemCertificate(t *testing.T, raw []byte) []byte {
	t.Helper()
	return []byte(fmt.Sprintf(
		"-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n",
		chunkBase64(base64.StdEncoding.EncodeToString(raw)),
	))
}

func chunkBase64(value string) string {
	var output strings.Builder
	for len(value) > 64 {
		output.WriteString(value[:64])
		output.WriteByte('\n')
		value = value[64:]
	}
	output.WriteString(value)
	output.WriteByte('\n')
	return output.String()
}
