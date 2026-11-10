package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig holds the server-side configuration.
type ServerConfig struct {
	Listen     string            `yaml:"listen"`
	TLS        TLSConfig         `yaml:"tls"`
	Passwords  []string          `yaml:"passwords"`
	Users      []UserConfig      `yaml:"users"` // Named users (alternative to passwords list).
	Fallback   string            `yaml:"fallback"`
	WebSocket  *WSConfig         `yaml:"websocket"`
	CoverSite  string            `yaml:"cover_site"` // Path to cover website files.
	Encryption *EncryptionConfig `yaml:"encryption"`

	// Pre-computed password hashes (not from YAML).
	PasswordHashes map[string]bool   `yaml:"-"`
	UserNames      map[string]string `yaml:"-"` // hash → username
	UserLimits     map[string]int64  `yaml:"-"` // username → bandwidth limit in bytes
	UserSpeeds     map[string]int64  `yaml:"-"` // username → speed limit in bytes/sec
}

// UserConfig represents a named user with their own password.
type UserConfig struct {
	Name         string `yaml:"name"`
	Password     string `yaml:"password"`
	MaxBandwidth string `yaml:"max_bandwidth"` // Total quota: "50GB", "unlimited"
	MaxSpeed     string `yaml:"max_speed"`     // Speed limit: "10MB" = 10MB/s, "unlimited"
}

// WSConfig holds WebSocket transport configuration.
type WSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"` // Secret WebSocket endpoint path.
}

// EncryptionConfig holds inner encryption settings.
type EncryptionConfig struct {
	Enabled bool   `yaml:"enabled"`
	Key     string `yaml:"key"` // Shared secret for inner encryption (separate from Trojan password).
}

// TLSConfig holds TLS certificate paths.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// ClientConfig holds the client-side configuration.
type ClientConfig struct {
	Server      string            `yaml:"server"`
	Password    string            `yaml:"password"`
	SNI         string            `yaml:"sni"`
	Listen      string            `yaml:"listen"`
	Fingerprint string            `yaml:"fingerprint"`
	Transport   string            `yaml:"transport"` // "tls", "ws" (WebSocket), or "grpc" (HTTP/2-style).
	WSPath      string            `yaml:"ws_path"`   // WebSocket/gRPC path (must match server).
	Encryption  *EncryptionConfig `yaml:"encryption"`

	// Pre-computed password hash (not from YAML).
	PasswordHash string `yaml:"-"`
}

// HashPassword computes the Trojan password hash: hex(SHA224(password)).
// The Trojan protocol uses SHA224, producing a 56-character hex string.
func HashPassword(password string) string {
	h := sha256.New224()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// LoadServerConfig reads and parses the server configuration file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.Fallback == "" {
		cfg.Fallback = "127.0.0.1:8080"
	}
	if cfg.WebSocket != nil && cfg.WebSocket.Path == "" {
		cfg.WebSocket.Path = "/ws"
	}

	// Pre-compute password hashes for fast lookup.
	cfg.PasswordHashes = make(map[string]bool)
	cfg.UserNames = make(map[string]string)
	cfg.UserLimits = make(map[string]int64)
	cfg.UserSpeeds = make(map[string]int64)

	for _, pw := range cfg.Passwords {
		cfg.PasswordHashes[HashPassword(pw)] = true
	}
	for _, u := range cfg.Users {
		h := HashPassword(u.Password)
		cfg.PasswordHashes[h] = true
		cfg.UserNames[h] = u.Name
	}

	return &cfg, nil
}

// LoadClientConfig reads and parses the client configuration file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = "chrome"
	}
	if cfg.Transport == "" {
		cfg.Transport = "tls"
	}
	if cfg.WSPath == "" {
		cfg.WSPath = "/ws"
	}

	cfg.PasswordHash = HashPassword(cfg.Password)

	return &cfg, nil
}
