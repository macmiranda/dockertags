package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name      string
		debug     bool
		wantError bool
	}{
		{
			name:      "debug enabled",
			debug:     true,
			wantError: false,
		},
		{
			name:      "debug disabled",
			debug:     false,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.debug)
			if client == nil {
				t.Error("NewClient() returned nil client when no error was expected")
			}
		})
	}
}

type testClient struct {
	httpClient *http.Client
	debug      bool
	auth       *Auth
}

func (c *testClient) getAuth(registry string) (*Auth, error) {
	return c.auth, nil
}

func (c *testClient) getCredentialsFromHelper(helper, registry string) (*Auth, error) {
	return &Auth{}, nil
}

func (c *testClient) loadDockerConfig() (*DockerConfig, error) {
	return &DockerConfig{}, nil
}

func (c *testClient) ListTags(ctx context.Context, registry, repository string) ([]string, error) {
	// Construct the API URL
	apiURL := fmt.Sprintf("http://%s/v2/%s/tags/list", registry, repository)
	if c.debug {
		fmt.Printf("Making request to: %s\n", apiURL)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if c.debug {
		fmt.Printf("Response status: %d\n", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var tagsResponse struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tagsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return tagsResponse.Tags, nil
}

func TestListTags(t *testing.T) {
	// Create a test server that simulates a Docker registry
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 4 || parts[0] != "v2" || parts[len(parts)-1] != "list" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		repo := strings.Join(parts[1:len(parts)-2], "/")
		if repo == "test/repo" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"test/repo","tags":["latest","v1.0.0"]}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := &testClient{
		httpClient: http.DefaultClient,
		debug:      false,
		auth:       &Auth{},
	}

	tests := []struct {
		name      string
		repo      string
		wantError bool
	}{
		{
			name:      "valid repository",
			repo:      "test/repo",
			wantError: false,
		},
		{
			name:      "invalid repository",
			repo:      "invalid/repo/name",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags, err := client.ListTags(context.Background(), server.URL[7:], tt.repo)
			if (err != nil) != tt.wantError {
				t.Errorf("ListTags() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if !tt.wantError && len(tags) == 0 {
				t.Error("ListTags() returned empty tags when no error was expected")
			}
		})
	}
}
