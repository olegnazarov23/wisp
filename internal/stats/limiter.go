package stats

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseBandwidth parses a human-readable bandwidth string into bytes.
// Supports: "500MB", "1GB", "10GB", "unlimited", "0" (= unlimited).
func ParseBandwidth(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))

	if s == "" || s == "0" || s == "UNLIMITED" {
		return 0, nil // 0 = unlimited
	}

	var multiplier int64
	var numStr string

	switch {
	case strings.HasSuffix(s, "TB"):
		multiplier = 1 << 40
		numStr = strings.TrimSuffix(s, "TB")
	case strings.HasSuffix(s, "GB"):
		multiplier = 1 << 30
		numStr = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		multiplier = 1 << 20
		numStr = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		multiplier = 1 << 10
		numStr = strings.TrimSuffix(s, "KB")
	default:
		// Try parsing as raw bytes.
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid bandwidth: %q", s)
		}
		return n, nil
	}

	numStr = strings.TrimSpace(numStr)
	n, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid bandwidth number: %q", numStr)
	}

	return int64(n * float64(multiplier)), nil
}

// SetLimit sets the bandwidth limit for a user (in bytes, 0 = unlimited).
func (t *Tracker) SetLimit(username string, limitBytes int64) {
	s := t.GetOrCreate(username)
	s.Limit.Store(limitBytes)
}

// IsOverLimit checks if a user has exceeded their bandwidth limit.
func (t *Tracker) IsOverLimit(username string) bool {
	v, ok := t.users.Load(username)
	if !ok {
		return false
	}
	s := v.(*UserStats)
	limit := s.Limit.Load()
	if limit == 0 {
		return false // Unlimited.
	}
	total := s.Upload.Load() + s.Download.Load()
	return total >= limit
}
