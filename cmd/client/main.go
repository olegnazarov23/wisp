package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/olegnazarov23/wisp/internal/proxy"
	"github.com/olegnazarov23/wisp/pkg/config"
)

// version is set in release builds: -ldflags "-X main.version=v0.2.0".
var version = "dev"

func main() {
	configPath := flag.String("config", "configs/client.yaml", "path to client config")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("wisp-client", version)
		return
	}
	log.Printf("wisp-client %s", version)

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	log.Printf("connecting to %s (SNI: %s, fingerprint: %s, pinned keys: %d, rotate: %v, noise: %v)",
		cfg.Server, cfg.SNI, cfg.Fingerprint, len(cfg.Pins), *cfg.Rotate, cfg.Noise)

	var encKey string
	if cfg.Encryption != nil && cfg.Encryption.Enabled {
		encKey = cfg.Encryption.Key
		log.Printf("inner encryption: enabled (XChaCha20-Poly1305)")
	}

	socks := &proxy.SOCKS5Server{
		ServerAddr:    cfg.Server,
		SNI:           cfg.SNI,
		Fingerprint:   cfg.Fingerprint,
		PasswordHash:  cfg.PasswordHash,
		Transport:     cfg.Transport,
		WSPath:        cfg.WSPath,
		EncryptionKey: encKey,
		EnableNoise:   cfg.Noise,
		Pins:          cfg.Pins,
	}
	if *cfg.Rotate {
		socks.RotateAfter = 10 * time.Minute
		socks.RotateBytes = 128 << 20
	}

	log.Fatal(socks.ListenAndServe(cfg.Listen))
}
