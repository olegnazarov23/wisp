package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/olegnazarov23/wisp/internal/stats"
)

const adminSocket = "/run/wisp-admin.sock"

// startAdmin starts a local-only HTTP admin endpoint on a Unix socket.
// Only accessible from the server itself (not exposed to the network).
func startAdmin() {
	os.Remove(adminSocket)
	listener, err := net.Listen("unix", adminSocket)
	if err != nil {
		log.Printf("admin: %v", err)
		return
	}
	os.Chmod(adminSocket, 0600)

	mux := http.NewServeMux()

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := stats.Global.JSON()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(data)
	})

	mux.HandleFunc("/stats/text", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		snapshots := stats.Global.Snapshot()
		if len(snapshots) == 0 {
			fmt.Fprintln(w, "No users connected yet.")
			return
		}
		fmt.Fprintln(w, stats.TextHeader())
		for _, s := range snapshots {
			fmt.Fprintln(w, s.String())
		}
	})

	go http.Serve(listener, mux)
	log.Printf("admin socket: %s", adminSocket)
}
