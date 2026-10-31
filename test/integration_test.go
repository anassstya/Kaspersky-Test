package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"kaspersky-test/handler"
	"kaspersky-test/service"
)

func TestThreatAPI(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("create database pool: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Ping(ctx); err != nil {
		t.Fatalf("connect to test database: %v", err)
	}

	mux := http.NewServeMux()
	handler.New(service.New(db)).Register(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	md5 := randomMD5(t)
	missingMD5 := randomMD5(t)
	for missingMD5 == md5 {
		missingMD5 = randomMD5(t)
	}

	t.Cleanup(func() {
		if _, err := db.Exec(context.Background(), "DELETE FROM threats WHERE md5 = ANY($1)", []string{md5, missingMD5}); err != nil {
			t.Errorf("clean up test records: %v", err)
		}
	})

	postBody := map[string]any{
		"md5":         md5,
		"name":        "Trojan.Win32.Generic",
		"type":        "trojan",
		"level":       "high",
		"status":      "confirmed",
		"description": "Integration test threat",
		"source":      "test",
	}

	t.Run("POST creates a threat", func(t *testing.T) {
		status, body := request(t, server.URL, http.MethodPost, "/info", postBody)
		assertStatus(t, status, http.StatusCreated, body)
		if body["md5"] != md5 || body["name"] != "Trojan.Win32.Generic" {
			t.Fatalf("unexpected response: %v", body)
		}
		if body["created_at"] == nil || body["updated_at"] == nil {
			t.Fatalf("timestamps are missing: %v", body)
		}
	})

	t.Run("GET returns the created threat", func(t *testing.T) {
		status, body := request(t, server.URL, http.MethodGet, "/info/"+md5, nil)
		assertStatus(t, status, http.StatusOK, body)
		if body["md5"] != md5 || body["level"] != "high" {
			t.Fatalf("unexpected response: %v", body)
		}
	})

	t.Run("POST duplicate returns 409", func(t *testing.T) {
		status, body := request(t, server.URL, http.MethodPost, "/info", postBody)
		assertStatus(t, status, http.StatusConflict, body)
		if body["code"] != "THREAT_ALREADY_EXISTS" {
			t.Fatalf("unexpected error response: %v", body)
		}
	})

	t.Run("PUT updates the threat", func(t *testing.T) {
		updateBody := map[string]any{
			"name":        "Trojan.Win32.Updated",
			"type":        "trojan",
			"level":       "critical",
			"status":      "confirmed",
			"description": "Updated threat",
		}
		status, body := request(t, server.URL, http.MethodPut, "/info/"+md5, updateBody)
		assertStatus(t, status, http.StatusOK, body)
		if body["name"] != "Trojan.Win32.Updated" || body["level"] != "critical" {
			t.Fatalf("unexpected updated response: %v", body)
		}

		status, body = request(t, server.URL, http.MethodGet, "/info/"+md5, nil)
		assertStatus(t, status, http.StatusOK, body)
		if body["level"] != "critical" {
			t.Fatalf("updated value was not saved: %v", body)
		}
	})

	t.Run("GET missing threat returns 404", func(t *testing.T) {
		status, body := request(t, server.URL, http.MethodGet, "/info/"+missingMD5, nil)
		assertStatus(t, status, http.StatusNotFound, body)
		if body["code"] != "THREAT_NOT_FOUND" {
			t.Fatalf("unexpected error response: %v", body)
		}
	})

	t.Run("PUT missing threat returns 404", func(t *testing.T) {
		status, body := request(t, server.URL, http.MethodPut, "/info/"+missingMD5, map[string]any{
			"name": "Trojan.Win32.Generic", "type": "trojan", "level": "high",
		})
		assertStatus(t, status, http.StatusNotFound, body)
	})

	t.Run("GET invalid MD5 returns 400", func(t *testing.T) {
		status, body := request(t, server.URL, http.MethodGet, "/info/invalid-md5", nil)
		assertStatus(t, status, http.StatusBadRequest, body)
	})

	t.Run("POST invalid threat returns 400", func(t *testing.T) {
		status, body := request(t, server.URL, http.MethodPost, "/info", map[string]any{
			"md5": randomMD5(t), "name": "x", "type": "trojan", "level": "high",
		})
		assertStatus(t, status, http.StatusBadRequest, body)
	})

	t.Run("POST malformed JSON returns 400", func(t *testing.T) {
		resp, err := http.Post(server.URL+"/info", "application/json", bytes.NewBufferString(`{"md5":`))
		if err != nil {
			t.Fatalf("send request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})
}

func randomMD5(t *testing.T) string {
	t.Helper()
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatalf("generate test MD5: %v", err)
	}
	return hex.EncodeToString(data[:])
}

func request(t *testing.T, baseURL, method, path string, payload any) (int, map[string]any) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer resp.Body.Close()

	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response (HTTP %d): %v", resp.StatusCode, err)
	}
	return resp.StatusCode, decoded
}

func assertStatus(t *testing.T, got, want int, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatal(fmt.Sprintf("expected HTTP %d, got %d; response: %v", want, got, body))
	}
}
