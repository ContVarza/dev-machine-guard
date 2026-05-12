package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestGzipBytes_RoundTrip(t *testing.T) {
	original := []byte(`{"customer_id":"acme","node_projects":[{"project_path":"/x"}]}`)
	compressed, err := gzipBytes(original)
	if err != nil {
		t.Fatalf("gzipBytes failed: %v", err)
	}
	if len(compressed) < 2 || compressed[0] != 0x1f || compressed[1] != 0x8b {
		t.Fatal("expected gzip magic bytes")
	}

	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	defer gz.Close()
	got, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("decompression failed: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, original)
	}
}

func TestUploadToS3_SendsCompressedBodyAndIsCompressedFlag(t *testing.T) {
	var (
		mu             sync.Mutex
		uploadURLBody  []byte
		putBody        []byte
		putContentType string
		notifyBody     []byte
	)

	// Mock S3 PUT endpoint — captures the body the agent uploads.
	// Emits x-amz-request-id so the client's "real AWS response" check
	// (uploadToS3 in telemetry.go) treats this 200 as genuine.
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		putBody = body
		putContentType = r.Header.Get("Content-Type")
		mu.Unlock()
		w.Header().Set("x-amz-request-id", "TESTREQID000000")
		w.Header().Set("x-amz-id-2", "test-id-2")
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Server.Close()

	// Mock backend — handles upload-URL, confirm-upload, and process-uploaded.
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			uploadURLBody = body
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": s3Server.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uploaded":   true,
				"size_bytes": 4242,
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			notifyBody = body
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()

	// Override config globals for the duration of the test.
	origEndpoint, origCustomer, origKey := config.APIEndpoint, config.CustomerID, config.APIKey
	config.APIEndpoint = backendServer.URL
	config.CustomerID = "test-customer"
	config.APIKey = "test-key"
	defer func() {
		config.APIEndpoint, config.CustomerID, config.APIKey = origEndpoint, origCustomer, origKey
	}()

	payload := &Payload{
		CustomerID: "test-customer",
		DeviceID:   "dev-1",
	}

	const testExecutionID = "11111111-2222-4333-8444-555555555555"
	if err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo), payload, testExecutionID); err != nil {
		t.Fatalf("uploadToS3 failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Upload-URL request body must include is_compressed: true.
	var uploadReq map[string]any
	if err := json.Unmarshal(uploadURLBody, &uploadReq); err != nil {
		t.Fatalf("failed to parse upload-URL request body: %v", err)
	}
	if uploadReq["device_id"] != "dev-1" {
		t.Errorf("expected device_id=dev-1, got %v", uploadReq["device_id"])
	}
	if uploadReq["is_compressed"] != true {
		t.Errorf("expected is_compressed=true, got %v", uploadReq["is_compressed"])
	}

	// PUT body must be gzip-compressed.
	if len(putBody) < 2 || putBody[0] != 0x1f || putBody[1] != 0x8b {
		t.Fatalf("expected gzip-compressed PUT body (got %d bytes)", len(putBody))
	}
	if putContentType != "application/json" {
		t.Errorf("expected Content-Type application/json (matches presigned URL), got %q", putContentType)
	}

	// Decompressing the PUT body should yield the original JSON payload.
	gz, err := gzip.NewReader(bytes.NewReader(putBody))
	if err != nil {
		t.Fatalf("PUT body is not valid gzip: %v", err)
	}
	defer gz.Close()
	decompressed, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("failed to decompress PUT body: %v", err)
	}
	var roundTrip Payload
	if err := json.Unmarshal(decompressed, &roundTrip); err != nil {
		t.Fatalf("decompressed body is not valid JSON: %v", err)
	}
	if roundTrip.DeviceID != "dev-1" {
		t.Errorf("decompressed payload device_id mismatch: got %q", roundTrip.DeviceID)
	}

	// Notify-backend was called with the s3_key returned from the upload-URL endpoint.
	var notify map[string]string
	if err := json.Unmarshal(notifyBody, &notify); err != nil {
		t.Fatalf("failed to parse notify body: %v", err)
	}
	if !strings.HasSuffix(notify["s3_key"], ".json.gz") {
		t.Errorf("expected s3_key with .json.gz suffix, got %q", notify["s3_key"])
	}
	if notify["execution_id"] != testExecutionID {
		t.Errorf("expected execution_id=%q in notify body, got %q", testExecutionID, notify["execution_id"])
	}
}

// TestUploadToS3_RejectsSynthetic200WithoutAWSHeaders simulates a TLS-inspecting
// proxy / DLP appliance that terminates the agent's outbound PUT to S3 and
// returns a synthetic "200 OK" without forwarding the body. A real S3 response
// always carries x-amz-request-id and x-amz-id-2 — the agent must treat a 200
// missing both as an upload failure rather than silently calling notify with
// an s3_key whose object was never persisted.
func TestUploadToS3_RejectsSynthetic200WithoutAWSHeaders(t *testing.T) {
	var notifyCalls atomic.Int32

	// Mock "proxy" responding 200 with no AWS headers — what a corporate
	// TLS interceptor produces when it terminates the PUT in-flight.
	fakeProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fake-proxy/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeProxy.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": fakeProxy.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			notifyCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()

	origEndpoint, origCustomer, origKey := config.APIEndpoint, config.CustomerID, config.APIKey
	config.APIEndpoint = backendServer.URL
	config.CustomerID = "test-customer"
	config.APIKey = "test-key"
	defer func() {
		config.APIEndpoint, config.CustomerID, config.APIKey = origEndpoint, origCustomer, origKey
	}()

	payload := &Payload{CustomerID: "test-customer", DeviceID: "dev-1"}
	err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo), payload, "11111111-2222-4333-8444-555555555555")
	if err == nil {
		t.Fatalf("uploadToS3 should fail when the PUT response is missing AWS request id headers")
	}
	if !strings.Contains(err.Error(), "not from AWS") {
		t.Errorf("expected error to mention 'not from AWS', got: %v", err)
	}
	if !strings.Contains(err.Error(), "fake-proxy/1.0") {
		t.Errorf("expected error to include the Server header hint, got: %v", err)
	}
	if got := notifyCalls.Load(); got != 0 {
		t.Errorf("notify endpoint must not be called when upload is rejected, got %d call(s)", got)
	}
}

// newAWSHeaderS3Server returns an httptest server that responds 200 to PUTs
// with the AWS request id headers a real S3 sets, so the agent's response
// verification accepts it.
func newAWSHeaderS3Server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-request-id", "TESTREQID000000")
		w.Header().Set("x-amz-id-2", "test-id-2")
		w.WriteHeader(http.StatusOK)
	}))
}

func withTestConfig(t *testing.T, endpoint string) {
	t.Helper()
	origEndpoint, origCustomer, origKey := config.APIEndpoint, config.CustomerID, config.APIKey
	config.APIEndpoint = endpoint
	config.CustomerID = "test-customer"
	config.APIKey = "test-key"
	t.Cleanup(func() {
		config.APIEndpoint, config.CustomerID, config.APIKey = origEndpoint, origCustomer, origKey
	})
}

// TestUploadToS3_ConfirmUploadFalseIsFatal exercises the "backend confirms
// the object is not in S3" branch — the PUT response looked real (AWS
// headers present) but the backend HEAD says nothing landed. The agent
// must bail and not call notify, because notify would only re-discover
// the same fact moments later.
func TestUploadToS3_ConfirmUploadFalseIsFatal(t *testing.T) {
	var notifyCalls atomic.Int32

	s3Server := newAWSHeaderS3Server(t)
	defer s3Server.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": s3Server.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uploaded": false,
				"reason":   "object_not_found",
				"s3_key":   "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			notifyCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()
	withTestConfig(t, backendServer.URL)

	err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo),
		&Payload{CustomerID: "test-customer", DeviceID: "dev-1"},
		"11111111-2222-4333-8444-555555555555")
	if err == nil {
		t.Fatal("uploadToS3 must fail when backend confirms upload is not in S3")
	}
	if !strings.Contains(err.Error(), "not in S3") {
		t.Errorf("expected error to mention 'not in S3', got: %v", err)
	}
	if !strings.Contains(err.Error(), "object_not_found") {
		t.Errorf("expected error to include the backend reason, got: %v", err)
	}
	if got := notifyCalls.Load(); got != 0 {
		t.Errorf("notify must not be called when confirm reports uploaded=false, got %d call(s)", got)
	}
}

// TestUploadToS3_ConfirmUpload404FallsThroughToNotify covers compatibility
// with older backends that don't expose /telemetry/confirm-upload yet.
// A 404 on confirm must NOT fail the run — notify still gets called and
// the upload completes via the existing flow.
func TestUploadToS3_ConfirmUpload404FallsThroughToNotify(t *testing.T) {
	var notifyCalls atomic.Int32

	s3Server := newAWSHeaderS3Server(t)
	defer s3Server.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": s3Server.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			// Simulate an old backend that doesn't know this route.
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			notifyCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()
	withTestConfig(t, backendServer.URL)

	err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo),
		&Payload{CustomerID: "test-customer", DeviceID: "dev-1"},
		"11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("uploadToS3 must succeed when confirm-upload is unsupported (404), got: %v", err)
	}
	if got := notifyCalls.Load(); got != 1 {
		t.Errorf("notify must still be called when confirm-upload returns 404, got %d call(s)", got)
	}
}

// TestUploadToS3_ConfirmUpload5xxFallsThroughToNotify covers transient
// backend failure of the confirm endpoint. The agent must not fail the
// run for that — notify still has its own server-side precheck.
func TestUploadToS3_ConfirmUpload5xxFallsThroughToNotify(t *testing.T) {
	var notifyCalls atomic.Int32

	s3Server := newAWSHeaderS3Server(t)
	defer s3Server.Close()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_url": s3Server.URL + "/put",
				"s3_key":     "developer-mdm/test-customer/dev-1/123.json.gz",
			})
		case strings.HasSuffix(r.URL.Path, "/telemetry/confirm-upload"):
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"s3_check_failed"}`))
		case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
			notifyCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backendServer.Close()
	withTestConfig(t, backendServer.URL)

	err := uploadToS3(context.Background(), progress.NewLogger(progress.LevelInfo),
		&Payload{CustomerID: "test-customer", DeviceID: "dev-1"},
		"11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("uploadToS3 must succeed when confirm-upload returns 5xx, got: %v", err)
	}
	if got := notifyCalls.Load(); got != 1 {
		t.Errorf("notify must still be called when confirm-upload returns 5xx, got %d call(s)", got)
	}
}
