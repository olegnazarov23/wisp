package main

import (
	"flag"
	"log"

	"github.com/olegnazarov23/wisp/internal/proxy"
	"github.com/olegnazarov23/wisp/pkg/config"
)

func main() {
	configPath := flag.String("config", "configs/client.yaml", "path to client config")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	log.Printf("connecting to %s (SNI: %s, fingerprint: %s)", cfg.Server, cfg.SNI, cfg.Fingerprint)

	var encKey string
	if cfg.Encryption != nil && cfg.Encryption.Enabled {
		encKey = cfg.Encryption.Key
		log.Printf("inner encryption: enabled (ChaCha20-Poly1305)")
	}

	socks := &proxy.SOCKS5Server{
		ServerAddr:    cfg.Server,
		SNI:           cfg.SNI,
		Fingerprint:   cfg.Fingerprint,
		PasswordHash:  cfg.PasswordHash,
		Transport:     cfg.Transport,
		WSPath:        cfg.WSPath,
		EncryptionKey: encKey,
		EnableNoise:   true, // Fake traffic to blend in.
	}

	log.Fatal(socks.ListenAndServe(cfg.Listen))
}
