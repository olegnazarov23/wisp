package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/olegnazarov23/wisp/internal/stats"
	"github.com/olegnazarov23/wisp/internal/tunnel"
	"github.com/olegnazarov23/wisp/pkg/config"
)

func main() {
	configPath := flag.String("config", "configs/server.yaml", "path to server config")
	printPin := flag.Bool("pin", false, "print the pin of the configured certificate's key, for clients' pins, and exit")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if *printPin {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
		if err != nil {
			log.Fatalf("load certificate: %v", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Fatalf("parse certificate: %v", err)
		}
		fmt.Println(tunnel.Pin(leaf))
		return
	}

	log.Printf("starting server on %s", cfg.Listen)
	log.Printf("fallback: %s", cfg.Fallback)
	if cfg.FallbackH2 != "" {
		log.Printf("fallback over HTTP/2: %s", cfg.FallbackH2)
	}
	log.Printf("users configured: %d", len(cfg.Users)+len(cfg.Passwords))

	// Start TLS listener.
	listener, err := tunnel.NewTLSListener(cfg.Listen, cfg.TLS.Cert, cfg.TLS.Key, cfg.FallbackH2 != "")
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
		FallbackH2Addr: cfg.FallbackH2,
		WSConfig:       cfg.WebSocket,
		CoverSiteDir:   cfg.CoverSite,
		EncryptionKey:  encKey,
		UserNames:      cfg.UserNames,
		UserSpeeds:     cfg.UserSpeeds,
		AllowPrivate:   cfg.AllowPrivate,
		Debug:          cfg.Debug,
	}
	if cfg.AllowPrivate {
		log.Printf("users may reach private addresses through the server")
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

	// back off on errors such as running out of file descriptors, instead of spinning
	var delay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			log.Printf("accept: %v; retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go handler.Handle(conn)
	}
}
