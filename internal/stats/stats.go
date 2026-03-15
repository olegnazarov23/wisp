package stats

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Tracker keeps per-user traffic statistics.
type Tracker struct {
	users sync.Map // username → *UserStats
}

// UserStats holds traffic counters for a single user.
type UserStats struct {
	Name        string
	Upload      atomic.Int64 // bytes sent by client (upstream)
	Download    atomic.Int64 // bytes received by client (downstream)
	Connections atomic.Int64 // total connections made
	Active      atomic.Int64 // currently active connections
	Limit       atomic.Int64 // bandwidth limit in bytes (0 = unlimited)
	FirstSeen   time.Time
	LastSeen    atomic.Value // time.Time
}

// Global tracker instance.
var Global = &Tracker{}

// GetOrCreate returns existing stats or creates new ones for a user.
func (t *Tracker) GetOrCreate(name string) *UserStats {
	if v, ok := t.users.Load(name); ok {
		return v.(*UserStats)
	}
	s := &UserStats{
		Name:      name,
		FirstSeen: time.Now(),
	}
	s.LastSeen.Store(time.Now())
	actual, _ := t.users.LoadOrStore(name, s)
	return actual.(*UserStats)
}

// Snapshot returns a point-in-time view of all user stats.
func (t *Tracker) Snapshot() []UserSnapshot {
	var result []UserSnapshot
	t.users.Range(func(key, value any) bool {
		s := value.(*UserStats)
		lastSeen, _ := s.LastSeen.Load().(time.Time)
		result = append(result, UserSnapshot{
			Name:        s.Name,
			Upload:      s.Upload.Load(),
			Download:    s.Download.Load(),
			Connections: s.Connections.Load(),
			Active:      s.Active.Load(),
			Limit:       s.Limit.Load(),
			FirstSeen:   s.FirstSeen,
			LastSeen:    lastSeen,
		})
		return true
	})
	return result
}

// UserSnapshot is a serializable snapshot of user stats.
type UserSnapshot struct {
	Name        string    `json:"name"`
	Upload      int64     `json:"upload_bytes"`
	Download    int64     `json:"download_bytes"`
	Connections int64     `json:"total_connections"`
	Active      int64     `json:"active_connections"`
	Limit       int64     `json:"limit_bytes"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

func (s UserSnapshot) String() string {
	limitStr := "unlimited"
	if s.Limit > 0 {
		total := s.Upload + s.Download
		pct := float64(total) / float64(s.Limit) * 100
		limitStr = fmt.Sprintf("%s / %s (%.0f%%)", formatBytes(total), formatBytes(s.Limit), pct)
	}
	return fmt.Sprintf("%-12s  up: %-10s  down: %-10s  quota: %-20s  conns: %d  last: %s",
		s.Name,
		formatBytes(s.Upload),
		formatBytes(s.Download),
		limitStr,
		s.Connections,
		time.Since(s.LastSeen).Truncate(time.Second),
	)
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// JSON returns stats as JSON.
func (t *Tracker) JSON() ([]byte, error) {
	return json.MarshalIndent(t.Snapshot(), "", "  ")
}

// CountedConn wraps a net.Conn and counts bytes read/written.
type CountedConn struct {
	net.Conn
	stats *UserStats
}

// WrapConn wraps a connection with byte counting for a user.
func WrapConn(conn net.Conn, username string) *CountedConn {
	s := Global.GetOrCreate(username)
	s.Connections.Add(1)
	s.Active.Add(1)
	s.LastSeen.Store(time.Now())
	return &CountedConn{Conn: conn, stats: s}
}

func (c *CountedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.stats.Upload.Add(int64(n)) // Client sending = upload.
	}
	return n, err
}

func (c *CountedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.stats.Download.Add(int64(n)) // Server sending to client = download.
	}
	return n, err
}

func (c *CountedConn) Close() error {
	c.stats.Active.Add(-1)
	c.stats.LastSeen.Store(time.Now())
	return c.Conn.Close()
}
