package mirror

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"
)

func TestTerminalProgressFitsWidth(t *testing.T) {
	s := Snapshot{Selected: 417350, Available: 100321, Failed: 2}
	for _, width := range []int{1, 20, 40, 60, 79, 100, 160} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			line := formatTerminalProgress(s, 99871, 15*time.Second, width)
			if len(line) > width || strings.ContainsAny(line, "\n\r\x1b") {
				t.Fatalf("progress wraps or contains control characters: %q", line)
			}
			if width >= 40 && (!strings.Contains(line, "ETA") || !strings.Contains(line, "2 failed")) {
				t.Fatalf("missing ETA or failure count: %q", line)
			}
			if width >= 79 && (!strings.Contains(line, "100,321/417,350") || !strings.Contains(line, "30.0/s")) {
				t.Fatalf("missing count or speed: %q", line)
			}
		})
	}
	t.Log(formatTerminalProgress(s, 99871, 15*time.Second, 99))
}

func TestTerminalProgressClearsAndFinishes(t *testing.T) {
	var output bytes.Buffer
	width := 80
	p := &syncProgress{out: &output, width: func() int { return width }}
	p.phase("Fetching a long inventory...")
	p.phase("Checking mirror...")
	p.update(Snapshot{Selected: 100, Available: 20}, 0, time.Second)
	width = 40 // A resize must not wrap subsequent updates.
	p.update(Snapshot{Selected: 100, Available: 30}, 0, 2*time.Second)
	if strings.Contains(output.String(), "\n") || strings.Count(output.String(), "\r\x1b[2K") != 4 {
		t.Fatalf("updates did not reuse and clear the same row: %q", output.String())
	}
	last := strings.Split(output.String(), "\r\x1b[2K")
	if len(last[len(last)-1]) >= width {
		t.Fatal("resized update reaches the last column")
	}
	errorText := "Download failed: " + strings.Repeat("x", 100)
	p.message("%s", errorText)
	if !strings.HasSuffix(output.String(), "\r\x1b[2K"+errorText+"\n") {
		t.Fatal("failure message is truncated or overlaps the bar")
	}
	p.update(Snapshot{Selected: 100, Available: 100}, 0, 3*time.Second)
	p.finish()
	before := output.String()
	p.finish()
	if output.String() != before || !strings.HasSuffix(before, "\n") {
		t.Fatal("finish must leave exactly one final newline")
	}
}

func TestRedirectedProgressHasNoTerminalEscapes(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	p := newSyncProgress()
	if p.width != nil {
		t.Fatal("redirected output detected as a terminal")
	}
	p.phase("Fetching inventory...")
	p.update(Snapshot{Selected: 100, Available: 50}, 0, time.Second)
	p.message("Sync incomplete")
	p.finish()
	if strings.ContainsAny(output.String(), "\r\x1b") || strings.Count(output.String(), "\n") != 3 {
		t.Fatalf("redirected logs contain terminal controls or missing lines: %q", output.String())
	}
}

func TestSyncTransferProgress(t *testing.T) {
	s := Snapshot{Selected: 100, Available: 20}
	for _, width := range []int{40, 79, 100, 160} {
		line := formatTerminalProgressWithTransfer(s, 0, 10*time.Second, width, "18.0 MiB/s")
		if len(line) > width || !strings.Contains(line, "ETA") {
			t.Fatalf("invalid progress at width %d: %q", width, line)
		}
		if width >= 100 && !strings.Contains(line, "18.0 MiB/s") {
			t.Fatalf("missing transfer rate: %q", line)
		}
	}
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	p := &syncProgress{receivedBytes: 180 << 20, fetched: 20, fetchTime: 40 * time.Second, processTime: 200 * time.Millisecond, writeTime: 50 * time.Millisecond}
	p.update(s, 0, 10*time.Second)
	for _, want := range []string{"18.0 MiB/s", "fetch=2s/doc", "process=10ms/doc", "writes=50ms"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q: %s", want, output.String())
		}
	}
}
