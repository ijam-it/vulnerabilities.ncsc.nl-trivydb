// Package mirror maintains a resumable, NCSC-only CSAF mirror.
package mirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

const Origin = "https://vulnerabilities.ncsc.nl"
const Directory = Origin + "/csaf/v2/"

var DocumentPath = regexp.MustCompile(`^[0-9]{4}/cve-[0-9]{4}-[0-9]{4,}\.json$`)
var buckets = []string{"documents", "revisions", "inventory", "metadata"}

const maxResponseBytes = 128 << 20

var compressors = sync.Pool{New: func() any {
	w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return w
}}

type Snapshot struct {
	Source     string    `json:"source"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Indexed    int       `json:"indexed"`
	Selected   int       `json:"selected"`
	Available  int       `json:"available"`
	Failed     int       `json:"failed"`
	Complete   bool      `json:"complete"`
}

type Options struct {
	Path              string
	Workers           int
	RequestsPerSecond float64
	Limit             int // Explicitly creates a partial mirror for development.
	WaitForMirror     bool
	ProgressInterval  time.Duration // Zero uses the default of five seconds.
}

type fetcher struct {
	client *http.Client
	base   string
	ticks  <-chan time.Time
}

func newFetcher(rps float64) (*fetcher, func()) {
	ticker := time.NewTicker(time.Duration(float64(time.Second) / rps))
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 32
	client := &http.Client{Transport: transport, Timeout: 90 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 || req.URL.Scheme != "https" || req.URL.Host != "vulnerabilities.ncsc.nl" {
				return errors.New("redirect outside NCSC origin refused")
			}
			return nil
		}}
	return &fetcher{client: client, base: Origin, ticks: ticker.C}, func() { ticker.Stop(); transport.CloseIdleConnections() }
}

func (f *fetcher) get(ctx context.Context, path string) ([]byte, error) {
	var last error
	for attempt := 0; attempt < 6; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.ticks:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "ncsc-trivy-db/1.0 (+NCSC-only CSAF mirror)")
		res, err := f.client.Do(req)
		wait := time.Duration(1<<attempt) * time.Second
		if err == nil {
			if res.StatusCode == http.StatusOK {
				b, readErr := readResponse(res)
				res.Body.Close()
				if readErr == nil {
					return b, nil
				}
				err = readErr
			} else {
				err = fmt.Errorf("HTTP %d for %s", res.StatusCode, path)
				if n, e := strconv.Atoi(res.Header.Get("Retry-After")); e == nil && n > 0 {
					wait = time.Duration(n) * time.Second
				}
				if t, e := http.ParseTime(res.Header.Get("Retry-After")); e == nil && time.Until(t) > wait {
					wait = time.Until(t)
				}
				io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
				res.Body.Close()
				if res.StatusCode != 429 && res.StatusCode < 500 {
					return nil, err
				}
			}
		}
		last = err
		if attempt < 5 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	return nil, last
}

// NCSC advisories can be many MiB. Allocate once when HTTP provides a size,
// avoiding ReadAll's repeated growth and copies across concurrent downloads.
// Check the actual length too, and retain the bound for chunked responses.
func readResponse(res *http.Response) ([]byte, error) {
	if res.ContentLength > maxResponseBytes {
		return nil, errors.New("response exceeds 128 MiB")
	}
	if res.ContentLength >= 0 {
		b := make([]byte, int(res.ContentLength))
		if _, err := io.ReadFull(res.Body, b); err != nil {
			return nil, err
		}
		var extra [1]byte
		if _, err := io.ReadFull(res.Body, extra[:]); err != io.EOF {
			if err == nil {
				err = errors.New("response exceeds Content-Length")
			}
			return nil, err
		}
		return b, nil
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err == nil && len(b) > maxResponseBytes {
		err = errors.New("response exceeds 128 MiB")
	}
	return b, err
}

func parseIndex(b []byte) ([]string, error) {
	seen := map[string]bool{}
	var paths []string
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.TrimSpace(line)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, Directory) {
			p = strings.TrimPrefix(p, Directory)
		}
		if !DocumentPath.MatchString(p) {
			return nil, fmt.Errorf("unsupported index entry %q", p)
		}
		if !seen[p] {
			paths = append(paths, p)
			seen[p] = true
		}
	}
	if len(paths) == 0 {
		return nil, errors.New("empty NCSC index")
	}
	sort.Strings(paths)
	return paths, nil
}

func parseChanges(b []byte) (map[string]string, error) {
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = 2
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, row := range rows {
		p := strings.TrimPrefix(strings.TrimSpace(row[0]), Directory)
		if !DocumentPath.MatchString(p) {
			return nil, fmt.Errorf("unsupported changes entry %q", p)
		}
		t, err := time.Parse(time.RFC3339Nano, row[1])
		if err != nil {
			return nil, err
		}
		if old, ok := out[p]; ok {
			o, _ := time.Parse(time.RFC3339Nano, old)
			if !t.After(o) {
				continue
			}
		}
		out[p] = row[1]
	}
	return out, nil
}

func Open(path string, readonly bool) (*bolt.DB, error) {
	if !readonly {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, err
		}
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: readonly, Timeout: time.Second})
	if errors.Is(err, bolt.ErrTimeout) {
		return nil, fmt.Errorf("database %q is locked by another process; if sync is running, wait for it to finish (build and sync also support --wait): %w", path, err)
	}
	return db, err
}

// OpenContext acquires the mirror before any provider metadata is fetched, so a
// queued refresh reads a fresh inventory after the preceding sync finishes.
func OpenContext(ctx context.Context, path string, readonly, wait bool) (*bolt.DB, error) {
	logged := false
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		db, err := Open(path, readonly)
		if !wait || !errors.Is(err, bolt.ErrTimeout) {
			return db, err
		}
		if !logged {
			log.Print("mirror is in use; waiting for its lock")
			logged = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func Compress(raw []byte) ([]byte, error) {
	var b bytes.Buffer
	w := compressors.Get().(*gzip.Writer)
	w.Reset(&b)
	defer func() {
		// Do not retain the completed document's output buffer in the pool.
		w.Reset(io.Discard)
		compressors.Put(w)
	}()
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func Decompress(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func ReadSnapshot(db *bolt.DB) (s Snapshot, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("metadata"))
		if b == nil {
			return errors.New("missing mirror metadata")
		}
		return json.Unmarshal(b.Get([]byte("snapshot")), &s)
	})
	return
}
func saveSnapshot(tx *bolt.Tx, s Snapshot) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return tx.Bucket([]byte("metadata")).Put([]byte("snapshot"), b)
}

func Sync(ctx context.Context, o Options) error {
	if o.Workers < 1 || o.Workers > 64 || math.IsNaN(o.RequestsPerSecond) || o.RequestsPerSecond <= 0 || o.RequestsPerSecond > 30 || o.Limit < 0 {
		return errors.New("workers must be 1..64; requests/sec must be >0 and <=30; limit must be >=0")
	}
	if o.ProgressInterval < 0 {
		return errors.New("progress interval must be >=0")
	}
	if o.ProgressInterval == 0 {
		o.ProgressInterval = 5 * time.Second
	}
	display := newSyncProgress()
	defer display.finish()
	db, err := OpenContext(ctx, o.Path, false, o.WaitForMirror)
	if err != nil {
		return err
	}
	defer db.Close()
	f, closeFetcher := newFetcher(o.RequestsPerSecond)
	defer closeFetcher()
	display.phase("Fetching NCSC provider metadata...")
	provider, err := f.get(ctx, "/csaf/provider-metadata.json")
	if err != nil {
		return err
	}
	var meta struct {
		Distributions []struct {
			DirectoryURL string `json:"directory_url"`
		} `json:"distributions"`
	}
	if err = json.Unmarshal(provider, &meta); err != nil {
		return err
	}
	supported := false
	for _, d := range meta.Distributions {
		if d.DirectoryURL == Directory {
			supported = true
		}
	}
	if !supported {
		return errors.New("NCSC no longer advertises CSAF v2; review format support before continuing")
	}
	display.phase("Fetching full CSAF index...")
	index, err := f.get(ctx, "/csaf/v2/index.txt")
	if err != nil {
		return err
	}
	paths, err := parseIndex(index)
	if err != nil {
		return err
	}
	display.phase("Fetching revisions for %s documents...", comma(len(paths)))
	changes, err := f.get(ctx, "/csaf/v2/changes.csv")
	if err != nil {
		return err
	}
	revisions, err := parseChanges(changes)
	if err != nil {
		return err
	}
	s := Snapshot{Source: Directory, StartedAt: time.Now().UTC(), Indexed: len(paths)}
	if o.Limit > 0 && o.Limit < len(paths) {
		paths = paths[:o.Limit]
	}
	s.Selected = len(paths)
	// The live index and revision listing can disagree. Keep every indexed
	// document, but require a fresh download when its upstream revision is
	// unknown. A token unique to this sync also keeps an older cached body stale
	// if the new download fails; it is never reused by a later sync.
	unlisted := 0
	for _, p := range paths {
		if revisions[p] == "" {
			revisions[p] = "unlisted:" + s.StartedAt.Format(time.RFC3339Nano)
			unlisted++
		}
	}
	if unlisted > 0 {
		display.message("%s indexed documents absent from changes.csv; downloading fresh copies", comma(unlisted))
	}
	display.phase("Checking mirror for unchanged documents...")
	var todo []string
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range buckets {
			if _, e := tx.CreateBucketIfNotExists([]byte(b)); e != nil {
				return e
			}
		}
		if e := tx.DeleteBucket([]byte("inventory")); e != nil {
			return e
		}
		inv, e := tx.CreateBucket([]byte("inventory"))
		if e != nil {
			return e
		}
		for _, p := range paths {
			rev := revisions[p]
			if e := inv.Put([]byte(p), []byte(rev)); e != nil {
				return e
			}
			if tx.Bucket([]byte("documents")).Get([]byte(p)) == nil || string(tx.Bucket([]byte("revisions")).Get([]byte(p))) != rev {
				todo = append(todo, p)
			} else {
				s.Available++
			}
		}
		m := tx.Bucket([]byte("metadata"))
		for k, v := range map[string][]byte{"provider-metadata.json": provider, "index.txt": index, "changes.csv": changes} {
			if e := m.Put([]byte(k), v); e != nil {
				return e
			}
		}
		return saveSnapshot(tx, s)
	})
	if err != nil {
		return err
	}
	display.message("NCSC sync | %s documents | %s selected", comma(s.Indexed), comma(s.Selected))
	display.message("%s reused | %s to download | limit %g req/s", comma(s.Available), comma(len(todo)), o.RequestsPerSecond)
	type result struct {
		path                   string
		body                   []byte
		err                    error
		bytes                  int
		fetchTime, processTime time.Duration
	}
	jobs := make(chan string)
	results := make(chan result, o.Workers)
	var wg sync.WaitGroup
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				fetchStarted := time.Now()
				b, e := f.get(ctx, "/csaf/v2/"+p)
				fetchTime := time.Since(fetchStarted)
				rawBytes := len(b)
				processStarted := time.Now()
				if e == nil {
					var d struct {
						Document struct {
							CSAFVersion string `json:"csaf_version"`
							Tracking    struct {
								ID string `json:"id"`
							} `json:"tracking"`
						} `json:"document"`
						Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
					}
					e = json.Unmarshal(b, &d)
					if e == nil && (d.Document.CSAFVersion != "2.0" || len(d.Vulnerabilities) == 0) {
						e = errors.New("not a nonempty CSAF 2.0 document")
					}
					expected := strings.ToUpper(strings.TrimSuffix(filepath.Base(p), ".json"))
					if e == nil && d.Document.Tracking.ID != expected {
						e = fmt.Errorf("document ID %q does not match %s", d.Document.Tracking.ID, expected)
					}
				}
				if e == nil {
					b, e = Compress(b)
				}
				results <- result{path: p, body: b, err: e, bytes: rawBytes, fetchTime: fetchTime, processTime: time.Since(processStarted)}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, p := range todo {
			select {
			case <-ctx.Done():
				return
			case jobs <- p:
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	started := time.Now()
	reused := s.Available
	progress := time.NewTicker(o.ProgressInterval)
	defer progress.Stop()
	flushTicker := time.NewTicker(time.Second)
	defer flushTicker.Stop()
	display.update(s, reused, 0)
	var writeErr error
	// Bolt commits are durable, but committing every advisory forces a disk sync
	// for every HTTP response. Bound both the time and memory spent in a batch.
	const maxBatchDocuments = 128
	const maxBatchBytes = 16 << 20
	var pending []result
	var pendingBytes int
	flush := func() {
		if len(pending) == 0 {
			return
		}
		writeStarted := time.Now()
		e := db.Update(func(tx *bolt.Tx) error {
			documents := tx.Bucket([]byte("documents"))
			revisionsBucket := tx.Bucket([]byte("revisions"))
			for _, r := range pending {
				if err := documents.Put([]byte(r.path), r.body); err != nil {
					return err
				}
				if err := revisionsBucket.Put([]byte(r.path), []byte(revisions[r.path])); err != nil {
					return err
				}
			}
			return nil
		})
		display.writeTime += time.Since(writeStarted)
		if e != nil {
			writeErr = e
			s.Failed += len(pending)
			display.message("Database write failed for %s documents: %v", comma(len(pending)), e)
		} else {
			s.Available += len(pending)
		}
		clear(pending)
		pending = pending[:0]
		pendingBytes = 0
	}
downloads:
	for {
		var r result
		select {
		case <-progress.C:
			display.update(s, reused, time.Since(started))
			if e := db.Update(func(tx *bolt.Tx) error { return saveSnapshot(tx, s) }); e != nil {
				writeErr = e
			}
			continue
		case <-flushTicker.C:
			flush()
			continue
		case next, ok := <-results:
			if !ok {
				break downloads
			}
			r = next
		}
		display.receivedBytes += int64(r.bytes)
		display.fetched++
		display.fetchTime += r.fetchTime
		display.processTime += r.processTime
		if r.err != nil {
			s.Failed++
			display.message("Download failed: %s: %v", r.path, r.err)
			continue
		}
		pending = append(pending, r)
		pendingBytes += len(r.body)
		if len(pending) >= maxBatchDocuments || pendingBytes >= maxBatchBytes {
			flush()
		}
	}
	flush()
	s.FinishedAt = time.Now().UTC()
	s.Complete = s.Available == s.Indexed && s.Selected == s.Indexed && s.Failed == 0 && ctx.Err() == nil
	if err = db.Update(func(tx *bolt.Tx) error { return saveSnapshot(tx, s) }); err != nil {
		return err
	}
	display.update(s, reused, time.Since(started))
	display.finish()
	if display.fetched > 0 {
		display.message("Pipeline | %.1f MiB received | fetch %s/doc | process %s/doc | database writes %s total",
			float64(display.receivedBytes)/(1<<20), (display.fetchTime / time.Duration(display.fetched)).Round(time.Millisecond),
			(display.processTime / time.Duration(display.fetched)).Round(time.Millisecond), display.writeTime.Round(time.Millisecond))
	}
	if s.Complete {
		display.message("Sync complete | %s documents available | %s downloaded in %s", comma(s.Available), comma(s.Available-reused), compactDuration(time.Since(started)))
	} else {
		display.message("Sync incomplete | %s/%s available | %s failed", comma(s.Available), comma(s.Indexed), comma(s.Failed))
	}
	if writeErr != nil {
		return writeErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.Failed > 0 {
		return fmt.Errorf("%d downloads failed; rerun sync to resume", s.Failed)
	}
	return nil
}

// formatProgress counts reused documents toward availability, but only downloads
// from this run toward throughput. Failed documents remain unavailable and need
// another sync; ETA covers the documents still pending in this run.
func formatProgress(s Snapshot, reused int, elapsed time.Duration) string {
	p := measureProgress(s, reused, elapsed)
	eta := "unknown"
	if p.etaKnown {
		eta = p.eta.String()
	}
	return fmt.Sprintf("mirror: %d/%d available (%.1f%%); downloaded=%d reused=%d failed=%d remaining=%d; %.1f docs/s; elapsed=%s ETA=%s",
		s.Available, s.Selected, p.percent, p.downloaded, reused, s.Failed, p.remaining, p.rate, elapsed.Truncate(time.Second), eta)
}

// ResolveDocumentURL never permits a path to escape the NCSC CSAF directory.
func ResolveDocumentURL(path string) (string, error) {
	if !DocumentPath.MatchString(path) {
		return "", errors.New("invalid CSAF path")
	}
	u, err := url.Parse(Directory + path)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
