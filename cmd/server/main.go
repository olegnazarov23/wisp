package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/awisp/wisp/internal/stats"
	"github.com/awisp/wisp/internal/tunnel"
	"github.com/awisp/wisp/pkg/config"
)

func main() {
	configPath := flag.String("config", "configs/server.yaml", "path to server config")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	log.Printf("starting server on %s", cfg.Listen)
	log.Printf("fallback: %s", cfg.Fallback)
	log.Printf("users configured: %d", len(cfg.Users)+len(cfg.Passwords))

	// Start TLS listener.
	listener, err := tunnel.NewTLSListener(cfg.Listen, cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		log.Fatalf("tls listener: %v", err)
	}
	defer listener.Close()

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		listener.Close()
		os.Exit(0)
	}()

	var encKey string
	if cfg.Encryption != nil && cfg.Encryption.Enabled {
		encKey = cfg.Encryption.Key
		log.Printf("inner encryption: enabled")
	}

	handler := &Handler{
		PasswordHashes: cfg.PasswordHashes,
		FallbackAddr:   cfg.Fallback,
		WSConfig:       cfg.WebSocket,
		CoverSiteDir:   cfg.CoverSite,
		EncryptionKey:  encKey,
		UserNames:      cfg.UserNames,
		UserSpeeds:     cfg.UserSpeeds,
	}

	// Set bandwidth and speed limits from config.
	for _, u := range cfg.Users {
		if u.MaxBandwidth != "" {
			limit, err := stats.ParseBandwidth(u.MaxBandwidth)
			if err != nil {
				log.Fatalf("invalid bandwidth for %s: %v", u.Name, err)
			}
			if limit > 0 {
				stats.Global.SetLimit(u.Name, limit)
				log.Printf("user %s: quota %s", u.Name, u.MaxBandwidth)
			}
		}
		if u.MaxSpeed != "" {
			speed, err := stats.ParseBandwidth(u.MaxSpeed)
			if err != nil {
				log.Fatalf("invalid speed for %s: %v", u.Name, err)
			}
			if speed > 0 {
				cfg.UserSpeeds[u.Name] = speed
				log.Printf("user %s: speed limit %s/s", u.Name, u.MaxSpeed)
			}
		}
	}

	startAdmin()
	log.Printf("server ready, accepting connections")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handler.Handle(conn)
	}
}
