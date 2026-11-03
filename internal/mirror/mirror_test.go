package mirror

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestInventories(t *testing.T) {
	paths, err := parseIndex([]byte("2024/cve-2024-1234.json\r\n2024/cve-2024-1234.json\r\n1999/cve-1999-0001.json\r\n"))
	if err != nil || !reflect.DeepEqual(paths, []string{"1999/cve-1999-0001.json", "2024/cve-2024-1234.json"}) {
		t.Fatal(paths, err)
	}
	for _, bad := range []string{"../secret.json", "https://example.org/a.json", "2024/../../secret.json", ""} {
		if _, e := parseIndex([]byte(bad)); e == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	r, e := parseChanges([]byte("\"2024/cve-2024-1234.json\",\"2026-10-28T17:30:35.898427+00:00\"\r\n"))
	if e != nil || len(r) != 1 {
		t.Fatal(r, e)
	}
}

func TestRetryAndCancellation(t *testing.T) {
	n := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer server.Close()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	f := fetcher{client: server.Client(), base: server.URL, ticks: tick.C}
	b, e := f.get(context.Background(), "/test")
	if e != nil || string(b) != "ok" || n != 2 {
		t.Fatal(string(b), e, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = f.get(ctx, "/test"); e == nil {
		t.Fatal("cancelled fetch succeeded")
	}
}

func TestLosslessCompression(t *testing.T) {
	raw := []byte("{\n  \"preserve_unknown_fields\": true\n}\n")
	b, e := Compress(raw)
	if e != nil {
		t.Fatal(e)
	}
	out, e := Decompress(b)
	if e != nil || string(out) != string(raw) {
		t.Fatal(string(out), e)
	}
}

func TestWaitForMirrorCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirror.db")
	db, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err = OpenContext(ctx, path, true, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestOpenExplainsLockTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirror.db")
	db, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = Open(path, true)
	if !errors.Is(err, bolt.ErrTimeout) {
		t.Fatalf("expected lock timeout, got %v", err)
	}
	for _, want := range []string{path, "locked by another process", "sync", "--wait"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not explain %q", err, want)
		}
	}
}

func TestNaNRateRejected(t *testing.T) {
	if err := Sync(context.Background(), Options{Workers: 1, RequestsPerSecond: math.NaN()}); err == nil {
		t.Fatal("NaN rate accepted")
	}
}

func TestFormatProgress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		s       Snapshot
		reused  int
		elapsed time.Duration
		want    string
	}{
		{"starting", Snapshot{Selected: 100}, 0, 0,
			"mirror: 0/100 available (0.0%); downloaded=0 reused=0 failed=0 remaining=100; 0.0 docs/s; elapsed=0s ETA=unknown"},
		{"resumed", Snapshot{Selected: 100, Available: 70, Failed: 5}, 50, 10 * time.Second,
			"mirror: 70/100 available (70.0%); downloaded=20 reused=50 failed=5 remaining=25; 2.0 docs/s; elapsed=10s ETA=13s"},
		{"all reused", Snapshot{Selected: 100, Available: 100}, 100, time.Second,
			"mirror: 100/100 available (100.0%); downloaded=0 reused=100 failed=0 remaining=0; 0.0 docs/s; elapsed=1s ETA=0s"},
		{"failed", Snapshot{Selected: 100, Available: 95, Failed: 5}, 0, 10 * time.Second,
			"mirror: 95/100 available (95.0%); downloaded=95 reused=0 failed=5 remaining=0; 9.5 docs/s; elapsed=10s ETA=0s"},
		{"empty", Snapshot{}, 0, 0,
			"mirror: 0/0 available (0.0%); downloaded=0 reused=0 failed=0 remaining=0; 0.0 docs/s; elapsed=0s ETA=0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatProgress(tc.s, tc.reused, tc.elapsed); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// progressLog lets the test observe heartbeat messages while HTTP is stalled.
type progressLog struct {
	mu   sync.Mutex
	text strings.Builder
	line chan string
}

func (w *progressLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.text.Write(p)
	select {
	case w.line <- string(p):
	default:
	}
	return len(p), nil
}

func routeNCSCToServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	// Route the production hostname to the local TLS fixture, with its test trust
	// configuration. No external requests are made.
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	previousTransport := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport; transport.CloseIdleConnections() })
}

func TestSyncMissingRevisions(t *testing.T) {
	const listed = "2024/cve-2024-1234.json"
	const unlisted = "2026/cve-2026-39735.json"
	var revisionListed, failing atomic.Bool
	var listedRequests, unlistedRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csaf/provider-metadata.json":
			fmt.Fprintf(w, `{"distributions":[{"directory_url":%q}]}`, Directory)
		case "/csaf/v2/index.txt":
			fmt.Fprintf(w, "%s\n%s\n", listed, unlisted)
		case "/csaf/v2/changes.csv":
			fmt.Fprintf(w, "%s,2026-10-28T00:00:00Z\n", listed)
			if revisionListed.Load() {
				fmt.Fprintf(w, "%s,2026-10-29T00:00:00Z\n", unlisted)
			}
		case "/csaf/v2/" + listed, "/csaf/v2/" + unlisted:
			if r.URL.Path == "/csaf/v2/"+unlisted {
				unlistedRequests.Add(1)
				if failing.Load() {
					http.NotFound(w, r)
					return
				}
			} else {
				listedRequests.Add(1)
			}
			id := strings.ToUpper(strings.TrimSuffix(filepath.Base(r.URL.Path), ".json"))
			fmt.Fprintf(w, `{"document":{"csaf_version":"2.0","tracking":{"id":%q}},"vulnerabilities":[{}]}`, id)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	routeNCSCToServer(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o := Options{Path: filepath.Join(t.TempDir(), "mirror.db"), Workers: 2, RequestsPerSecond: 30}
	for _, step := range []struct {
		name          string
		listed, fail  bool
		wantDownloads int32
	}{
		{"initial missing revision", false, false, 1},
		{"missing revision is fetched again", false, false, 2},
		{"failed refresh keeps cached body stale", false, true, 3},
		{"revision becomes available", true, false, 4},
		{"known revision is reused", true, false, 4},
	} {
		t.Run(step.name, func(t *testing.T) {
			revisionListed.Store(step.listed)
			failing.Store(step.fail)
			err := Sync(ctx, o)
			if step.fail {
				if err == nil || !strings.Contains(err.Error(), "1 downloads failed") {
					t.Fatalf("expected download failure, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if listedRequests.Load() != 1 || unlistedRequests.Load() != step.wantDownloads {
				t.Fatalf("downloads: listed=%d, unlisted=%d; want 1, %d", listedRequests.Load(), unlistedRequests.Load(), step.wantDownloads)
			}
			db, err := Open(o.Path, true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			snapshot, err := ReadSnapshot(db)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Complete != !step.fail || snapshot.Indexed != 2 || snapshot.Selected != 2 {
				t.Fatalf("unexpected snapshot: %+v", snapshot)
			}
			if step.fail && (snapshot.Available != 1 || snapshot.Failed != 1) {
				t.Fatalf("failed download counted as available: %+v", snapshot)
			}
			if err := db.View(func(tx *bolt.Tx) error {
				key := []byte(unlisted)
				if tx.Bucket([]byte("documents")).Get(key) == nil {
					return errors.New("cached document lost")
				}
				inventory := string(tx.Bucket([]byte("inventory")).Get(key))
				revision := string(tx.Bucket([]byte("revisions")).Get(key))
				if inventory == "" || (inventory == revision) == step.fail {
					return fmt.Errorf("unexpected revision freshness: inventory=%q cached=%q", inventory, revision)
				}
				changes := string(tx.Bucket([]byte("metadata")).Get([]byte("changes.csv")))
				if strings.Contains(changes, unlisted) != step.listed || strings.Contains(changes, "unlisted:") {
					return fmt.Errorf("upstream changes.csv was altered: %q", changes)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSyncProgressWhileStalledAndResuming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release := make(chan struct{})
	var failing atomic.Bool
	failing.Store(true)
	var firstRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csaf/provider-metadata.json":
			fmt.Fprintf(w, `{"distributions":[{"directory_url":%q}]}`, Directory)
		case "/csaf/v2/index.txt":
			fmt.Fprint(w, "2024/cve-2024-1234.json\n2024/cve-2024-5678.json\n")
		case "/csaf/v2/changes.csv":
			fmt.Fprint(w, "2024/cve-2024-1234.json,2026-10-28T00:00:00Z\n2024/cve-2024-5678.json,2026-10-28T00:00:00Z\n")
		default:
			if strings.HasSuffix(r.URL.Path, "1234.json") {
				firstRequests.Add(1)
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			if strings.HasSuffix(r.URL.Path, "5678.json") && failing.Load() {
				http.Error(w, "failed", http.StatusBadRequest)
				return
			}
			id := strings.ToUpper(strings.TrimSuffix(filepath.Base(r.URL.Path), ".json"))
			fmt.Fprintf(w, `{"document":{"csaf_version":"2.0","tracking":{"id":%q}},"vulnerabilities":[{}]}`, id)
		}
	}))
	defer server.Close()
	routeNCSCToServer(t, server)
	output := &progressLog{line: make(chan string, 100)}
	previousOutput := log.Writer()
	log.SetOutput(output)
	defer log.SetOutput(previousOutput)
	o := Options{Path: filepath.Join(t.TempDir(), "mirror.db"), Workers: 2, RequestsPerSecond: 30, ProgressInterval: 10 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- Sync(ctx, o) }()
	// The initial message plus two timer updates must arrive with no results.
	heartbeats := 0
	for heartbeats < 3 {
		select {
		case line := <-output.line:
			if strings.Contains(line, "mirror: 0/2 available") {
				heartbeats++
			}
		case <-ctx.Done():
			<-done
			output.mu.Lock()
			messages := output.text.String()
			output.mu.Unlock()
			t.Fatalf("no periodic progress while downloads stalled:\n%s", messages)
		case err := <-done:
			t.Fatalf("sync exited before periodic progress: %v", err)
		}
	}
	close(release)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "1 downloads failed") {
		t.Fatalf("expected failed sync, got %v", err)
	}
	failing.Store(false)
	if err := Sync(ctx, o); err != nil {
		t.Fatal(err)
	}
	if firstRequests.Load() != 1 {
		t.Fatal("resumed sync downloaded an unchanged document again")
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	for _, want := range []string{
		"downloaded=1 reused=0 failed=1 remaining=0",
		"mirror: 2/2 available (100.0%); downloaded=1 reused=1 failed=0 remaining=0",
		"Sync complete",
	} {
		if !strings.Contains(output.text.String(), want) {
			t.Fatalf("missing %q in logs:\n%s", want, output.text.String())
		}
	}
}

func TestSyncTimedBatchFlushSurvivesInterruption(t *testing.T) {
	paths := []string{
		"2024/cve-2024-1234.json",
		"2024/cve-2024-5678.json",
		"2024/cve-2024-9012.json",
	}
	var requests [3]atomic.Int32
	stalled := make(chan struct{}, 1)
	var blockLast atomic.Bool
	blockLast.Store(true)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csaf/provider-metadata.json":
			fmt.Fprintf(w, `{"distributions":[{"directory_url":%q}]}`, Directory)
		case "/csaf/v2/index.txt":
			fmt.Fprint(w, strings.Join(paths, "\n")+"\n")
		case "/csaf/v2/changes.csv":
			for _, p := range paths {
				fmt.Fprintf(w, "%s,2026-10-28T00:00:00Z\n", p)
			}
		default:
			for i, p := range paths {
				if r.URL.Path != "/csaf/v2/"+p {
					continue
				}
				requests[i].Add(1)
				if i == 2 && blockLast.Load() {
					select {
					case stalled <- struct{}{}:
					default:
					}
					<-r.Context().Done()
					return
				}
				id := strings.ToUpper(strings.TrimSuffix(filepath.Base(p), ".json"))
				fmt.Fprintf(w, `{"document":{"csaf_version":"2.0","tracking":{"id":%q}},"vulnerabilities":[{}]}`, id)
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	routeNCSCToServer(t, server)
	o := Options{Path: filepath.Join(t.TempDir(), "mirror.db"), Workers: 2, RequestsPerSecond: 30}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- Sync(ctx, o) }()
	select {
	case <-stalled:
	case <-ctx.Done():
		t.Fatal("last request did not stall")
	}
	// The first two results are persisted by the one-second flush while the
	// final request is still pending.
	time.Sleep(1200 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted sync returned %v", err)
	}
	blockLast.Store(false)
	if err := Sync(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	for i, n := range requests {
		want := int32(1)
		if i == 2 {
			want = 2 // The interrupted request must be fetched again.
		}
		if n.Load() != want {
			t.Fatalf("document %d downloaded %d times after resume, want %d", i, n.Load(), want)
		}
	}
}

func TestNegativeProgressIntervalRejected(t *testing.T) {
	err := Sync(context.Background(), Options{Workers: 1, RequestsPerSecond: 30, ProgressInterval: -time.Second})
	if err == nil || !strings.Contains(err.Error(), "progress interval") {
		t.Fatalf("expected invalid progress interval error, got %v", err)
	}
}
