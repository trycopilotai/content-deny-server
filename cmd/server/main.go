// Command server answers whether a host is on the content deny list.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/trycopilotai/content-deny-server/internal/denylist"
)

// maxBodyBytes caps a POST /denied body. A larger body gets 413
// without being read, so one request cannot hold an unbounded body
// or an unbounded response in memory.
const maxBodyBytes = 1 << 20

// set is written once, before ready is stored true, and only read
// after a handler observes ready as true.
var (
	set   *denylist.Set
	ready atomic.Bool
)

type result struct {
	Host       string `json:"host"`
	Normalized string `json:"normalized"`
	Denied     bool   `json:"denied"`
}

type errorBody struct {
	Error string `json:"error"`
}

func check(host string) result {
	return result{
		Host:       host,
		Normalized: denylist.Normalize(host),
		Denied:     set.Denied(host),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func handleDeniedGet(w http.ResponseWriter, r *http.Request) {
	if !ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"loading"})
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{"host required"})
		return
	}
	writeJSON(w, http.StatusOK, check(host))
}

// handleDeniedPost answers a batch. The body must be a JSON object
// whose "hosts" key, matched exactly, holds an array of strings. A
// missing or null "hosts" is 400, so a misspelt key cannot pass as an
// empty batch. An element that is "" or null is a missing host, which
// is 400 for the whole request, as it is for GET; no partial results
// are returned. Every other string, valid or not, gets a result.
func handleDeniedPost(w http.ResponseWriter, r *http.Request) {
	if !ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"loading"})
		return
	}
	if r.ContentLength > maxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{"body too large"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{"body too large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, errorBody{"cannot read body"})
		return
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{"malformed JSON"})
		return
	}
	raw, ok := fields["hosts"]
	if !ok || string(raw) == "null" {
		writeJSON(w, http.StatusBadRequest, errorBody{"hosts required"})
		return
	}
	var hosts []string
	if err := json.Unmarshal(raw, &hosts); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{"malformed JSON"})
		return
	}
	results := make([]result, 0, len(hosts))
	for _, host := range hosts {
		if host == "" {
			writeJSON(w, http.StatusBadRequest, errorBody{"host required"})
			return
		}
		results = append(results, check(host))
	}
	writeJSON(w, http.StatusOK, struct {
		Results []result `json:"results"`
	}{results})
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if !ready.Load() {
		writeText(w, http.StatusServiceUnavailable, "loading\n")
		return
	}
	writeText(w, http.StatusOK, "ok\n")
}

func handleVersion(image, listRevision string) http.HandlerFunc {
	body := struct {
		Image        string `json:"image"`
		ListRevision string `json:"list_revision"`
	}{image, listRevision}
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, body)
	}
}

// load reads the list and refuses an empty one: a server holding no
// domains would allow every host, so it exits instead of reporting
// healthy.
func load(path string) (*denylist.Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := denylist.Load(f)
	if err != nil {
		return nil, err
	}
	if s.Len() == 0 {
		return nil, errors.New("no domains")
	}
	return s, nil
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	data := flag.String("data", "/data/denylist.txt", "sorted domain list, one per line")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /denied", handleDeniedGet)
	mux.HandleFunc("POST /denied", handleDeniedPost)
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /version", handleVersion(os.Getenv("IMAGE_TAG"), os.Getenv("LIST_REVISION")))

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	// ReadTimeout bounds the whole request, body included, and is
	// also the keep-alive idle limit. WriteTimeout bounds a client
	// that stops reading its response.
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Printf("listening on %s", ln.Addr())

	s, err := load(*data)
	if err != nil {
		log.Fatalf("load %s: %v", *data, err)
	}
	set = s
	// Loading leaves the grown-and-retired copies of the blob and
	// offsets in the heap; hand them back to the OS before serving.
	debug.FreeOSMemory()
	ready.Store(true)
	log.Printf("loaded %d domains from %s", s.Len(), *data)

	log.Fatal(<-served)
}
