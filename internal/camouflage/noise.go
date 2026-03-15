package camouflage

import (
	"crypto/rand"
	"math/big"
	"time"
)

// NoiseGenerator produces fake traffic that mimics normal browsing patterns.
// It runs in the background on idle mux sessions to prevent traffic analysis
// from detecting "no traffic = not browsing, traffic = VPN active" patterns.
type NoiseGenerator struct {
	// MinInterval and MaxInterval control how often fake traffic is sent.
	MinInterval time.Duration
	MaxInterval time.Duration
	// MinSize and MaxSize control fake payload sizes.
	MinSize int
	MaxSize int
	// SendFunc is called with the fake payload to send.
	SendFunc func([]byte) error
	stopCh   chan struct{}
}

// NewNoiseGenerator creates a generator with sensible defaults.
// Fake traffic every 2-8 seconds, 64-1460 bytes (mimics small HTTP requests).
func NewNoiseGenerator(sendFunc func([]byte) error) *NoiseGenerator {
	return &NoiseGenerator{
		MinInterval: 2 * time.Second,
		MaxInterval: 8 * time.Second,
		MinSize:     64,
		MaxSize:     1460, // Common MSS size — looks like real TCP segments.
		SendFunc:    sendFunc,
		stopCh:      make(chan struct{}),
	}
}

// Start begins generating fake traffic in the background.
func (ng *NoiseGenerator) Start() {
	go ng.loop()
}

// Stop stops the noise generator.
func (ng *NoiseGenerator) Stop() {
	select {
	case <-ng.stopCh:
	default:
		close(ng.stopCh)
	}
}

func (ng *NoiseGenerator) loop() {
	for {
		interval := ng.randomDuration()
		select {
		case <-time.After(interval):
			payload := ng.generatePayload()
			if err := ng.SendFunc(payload); err != nil {
				return // Connection likely closed.
			}
		case <-ng.stopCh:
			return
		}
	}
}

func (ng *NoiseGenerator) randomDuration() time.Duration {
	diff := ng.MaxInterval - ng.MinInterval
	if diff <= 0 {
		return ng.MinInterval
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	return ng.MinInterval + time.Duration(n.Int64())
}

func (ng *NoiseGenerator) generatePayload() []byte {
	size := ng.MinSize
	diff := ng.MaxSize - ng.MinSize
	if diff > 0 {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(diff)))
		size += int(n.Int64())
	}

	// Generate data that looks like HTTP at a glance — starts with plausible
	// HTTP-like bytes rather than pure random (which is detectable).
	payload := make([]byte, size)

	// Prefix with a realistic HTTP fragment.
	httpFragments := []string{
		"GET /assets/main.js HTTP/1.1\r\nHost: ",
		"POST /api/telemetry HTTP/1.1\r\nContent-Type: application/json\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
		"GET /images/logo.png HTTP/1.1\r\nAccept: image/webp\r\n",
		"{\"status\":\"ok\",\"timestamp\":",
		"<!DOCTYPE html><html><head><meta charset=\"utf-8\">",
	}

	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(httpFragments))))
	fragment := httpFragments[idx.Int64()]

	copy(payload, []byte(fragment))
	// Fill the rest with random bytes.
	if len(fragment) < size {
		rand.Read(payload[len(fragment):])
	}

	return payload
}
