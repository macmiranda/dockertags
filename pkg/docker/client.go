package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DockerConfig represents the structure of the Docker config file
type DockerConfig struct {
	Auths       map[string]AuthConfig `json:"auths"`
	CredsStore  string                `json:"credsStore,omitempty"`
	CredHelpers map[string]string     `json:"credHelpers,omitempty"`
}

// AuthConfig represents the authentication configuration for a registry
type AuthConfig struct {
	Auth string `json:"auth,omitempty"`
}

// Auth represents decoded authentication credentials
type Auth struct {
	Username string
	Password string
}

// Client represents a Docker registry client
type Client struct {
	httpClient *http.Client
	debug      bool
}

// NewClient creates a new Docker registry client
func NewClient(debug bool) *Client {
	return &Client{
		httpClient: &http.Client{},
		debug:      debug,
	}
}

// debugf prints a debug message if debug mode is enabled
func (c *Client) debugf(format string, args ...interface{}) {
	if c.debug {
		fmt.Printf("Debug: "+format+"\n", args...)
	}
}

// ListTags lists all tags for a given repository
func (c *Client) ListTags(ctx context.Context, registry, repository string) ([]string, error) {
	// For Docker Hub, we need to handle the library/ prefix
	if registry == "docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}

	// Get authentication from docker config
	auth, err := c.getAuth(registry)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth: %w", err)
	}

	c.debugf("Using auth for registry %s", registry)
	if auth.Username != "" {
		c.debugf("Found username: %s", auth.Username)
	}

	// For Docker Hub, we need to get a token first
	var token string
	if registry == "docker.io" {
		token, err = c.getDockerHubToken(ctx, repository, auth)
		if err != nil {
			c.debugf("Failed to get Docker Hub token: %v", err)
			// Continue without token
		}
		if token != "" {
			c.debugf("Got Docker Hub token")
		}
	}

	// For Docker Hub, use the official registry URL
	registryURL := registry
	if registry == "docker.io" {
		registryURL = "registry-1.docker.io"
	}

	// Construct the API URL
	apiURL := fmt.Sprintf("https://%s/v2/%s/tags/list", registryURL, repository)
	c.debugf("Making request to: %s", apiURL)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		c.debugf("Using Bearer token")
	} else if auth.Username != "" && auth.Password != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", c.getBasicAuthToken(auth)))
		c.debugf("Using Basic auth")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	c.debugf("Response status: %d", resp.StatusCode)

	if resp.StatusCode == http.StatusUnauthorized {
		// Check for WWW-Authenticate header
		authHeader := resp.Header.Get("WWW-Authenticate")
		if authHeader != "" {
			c.debugf("Got WWW-Authenticate header: %s", authHeader)
			token, err = c.handleAuthChallenge(ctx, authHeader, repository, auth)
			if err != nil {
				return nil, fmt.Errorf("failed to handle auth challenge: %w", err)
			}

			// Retry the request with the token
			req, err = http.NewRequestWithContext(ctx, "GET", apiURL, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			c.debugf("Using Bearer token from auth challenge")

			resp, err = c.httpClient.Do(req)
			if err != nil {
				return nil, fmt.Errorf("failed to make request: %w", err)
			}
			defer resp.Body.Close()

			c.debugf("Response status after auth: %d", resp.StatusCode)
		}

		if resp.StatusCode == http.StatusUnauthorized {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("unauthorized: %s", string(body))
		}
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

// getAuth retrieves authentication credentials for a registry
func (c *Client) getAuth(registry string) (*Auth, error) {
	config, err := c.loadDockerConfig()
	if err != nil {
		// If we can't load config, continue without auth
		c.debugf("Failed to load docker config: %v", err)
		return &Auth{}, nil
	}

	// Try to get credentials from credential helper first
	if helper := c.getCredentialHelper(config, registry); helper != "" {
		creds, err := c.getCredentialsFromHelper(helper, registry)
		if err != nil {
			// If helper fails, continue without those credentials
			c.debugf("Failed to get credentials from helper: %v", err)
		} else if creds != nil {
			return creds, nil
		}
	}

	// Try direct auth config
	if auth, ok := config.Auths[registry]; ok && auth.Auth != "" {
		return decodeAuth(auth.Auth)
	}

	// Try with https:// prefix
	if auth, ok := config.Auths["https://"+registry]; ok && auth.Auth != "" {
		return decodeAuth(auth.Auth)
	}

	// Try with http:// prefix
	if auth, ok := config.Auths["http://"+registry]; ok && auth.Auth != "" {
		return decodeAuth(auth.Auth)
	}

	// For Docker Hub, try docker.io
	if registry == "docker.io" {
		if auth, ok := config.Auths["https://index.docker.io/v1/"]; ok && auth.Auth != "" {
			return decodeAuth(auth.Auth)
		}
	}

	// If no auth found, continue without credentials
	return &Auth{}, nil
}

// getCredentialHelper returns the credential helper for a registry
func (c *Client) getCredentialHelper(config *DockerConfig, registry string) string {
	// Check registry-specific helpers
	if helper, ok := config.CredHelpers[registry]; ok {
		return helper
	}

	// Check default helper
	return config.CredsStore
}

// getCredentialsFromHelper retrieves credentials from a credential helper
func (c *Client) getCredentialsFromHelper(helper, registry string) (*Auth, error) {
	cmd := exec.Command("docker-credential-"+helper, "get")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, registry+"\n")
	}()

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var creds struct {
		Username string `json:"Username"`
		Secret   string `json:"Secret"`
	}
	if err := json.Unmarshal(output, &creds); err != nil {
		return nil, err
	}

	if creds.Username == "" || creds.Secret == "" {
		return nil, nil
	}

	return &Auth{
		Username: creds.Username,
		Password: creds.Secret,
	}, nil
}

// loadDockerConfig loads the Docker configuration file
func (c *Client) loadDockerConfig() (*DockerConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(home, ".docker", "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config DockerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// decodeAuth decodes base64-encoded authentication string
func decodeAuth(auth string) (*Auth, error) {
	if auth == "" {
		return &Auth{}, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid auth format")
	}

	return &Auth{
		Username: parts[0],
		Password: parts[1],
	}, nil
}

// getBasicAuthToken generates a Basic authentication token
func (c *Client) getBasicAuthToken(auth *Auth) string {
	if auth.Username == "" || auth.Password == "" {
		return ""
	}
	authStr := fmt.Sprintf("%s:%s", auth.Username, auth.Password)
	return base64.StdEncoding.EncodeToString([]byte(authStr))
}

// getDockerHubToken retrieves a token from Docker Hub
func (c *Client) getDockerHubToken(ctx context.Context, repository string, auth *Auth) (string, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "auth.docker.io",
		Path:   "/token",
	}

	q := u.Query()
	q.Set("service", "registry.docker.io")
	q.Set("scope", fmt.Sprintf("repository:%s:pull", repository))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", err
	}

	if auth.Username != "" && auth.Password != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", c.getBasicAuthToken(auth)))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get token: %s", string(body))
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.Token, nil
}

func (c *Client) handleAuthChallenge(ctx context.Context, authHeader, repository string, auth *Auth) (string, error) {
	// Parse the WWW-Authenticate header
	// Example: Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:library/nginx:pull"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("unsupported auth challenge: %s", authHeader)
	}

	params := make(map[string]string)
	for _, param := range strings.Split(parts[1], ",") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := kv[0]
		value := strings.Trim(kv[1], `"`)
		params[key] = value
	}

	realm := params["realm"]
	service := params["service"]
	scope := params["scope"]

	if realm == "" {
		return "", fmt.Errorf("missing realm in auth challenge")
	}

	// Build the token request URL
	u, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("invalid realm URL: %w", err)
	}

	q := u.Query()
	if service != "" {
		q.Set("service", service)
	}
	if scope != "" {
		q.Set("scope", scope)
	} else {
		q.Set("scope", fmt.Sprintf("repository:%s:pull", repository))
	}
	u.RawQuery = q.Encode()

	// Make the token request
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	if auth.Username != "" && auth.Password != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", c.getBasicAuthToken(auth)))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get token: %s", string(body))
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.Token, nil
}
