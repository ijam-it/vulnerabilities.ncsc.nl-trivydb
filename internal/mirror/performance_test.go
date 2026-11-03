package mirror

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
)

func TestReadResponse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		length  int64
		wantErr bool
	}{
		{"known length", "advisory", 8, false},
		{"unknown length", "advisory", -1, false},
		{"empty", "", 0, false},
		{"empty stream", "", -1, false},
		{"truncated", "short", 8, true},
		{"overlong", "too long", 3, true},
		{"oversized", "", maxResponseBytes + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &http.Response{Body: io.NopCloser(bytes.NewBufferString(tc.body)), ContentLength: tc.length}
			body, err := readResponse(res)
			if (err != nil) != tc.wantErr {
				t.Fatalf("readResponse returned %q, %v", body, err)
			}
			if err == nil && string(body) != tc.body {
				t.Fatalf("got %q, want %q", body, tc.body)
			}
			if tc.name == "truncated" && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated response returned %v", err)
			}
		})
	}
}

func TestCompressConcurrentReuse(t *testing.T) {
	for i := 0; i < 16; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			var compressed [][]byte
			var originals [][]byte
			for _, size := range []int{0, 7, 1 << 20, 100} {
				raw := bytes.Repeat([]byte{byte(i)}, size)
				body, err := Compress(raw)
				if err != nil {
					t.Fatal(err)
				}
				compressed = append(compressed, body)
				originals = append(originals, raw)
			}
			// Later reuse must not mutate previously returned compressed bodies.
			for j, body := range compressed {
				raw, err := Decompress(body)
				if err != nil || !bytes.Equal(raw, originals[j]) {
					t.Fatalf("document %d changed after compressor reuse: %v", j, err)
				}
			}
		})
	}
}

func benchmarkAdvisory(b *testing.B) []byte {
	b.Helper()
	compressed, err := os.ReadFile("../../testdata/ncsc/cve-2025-22153.json.gz")
	if err != nil {
		b.Fatal(err)
	}
	raw, err := Decompress(compressed)
	if err != nil {
		b.Fatal(err)
	}
	return raw
}

func BenchmarkCompress(b *testing.B) {
	raw := benchmarkAdvisory(b)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := Compress(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadAdvisory(b *testing.B) {
	fixture := benchmarkAdvisory(b)
	for _, size := range []int{len(fixture), 9 << 20} {
		raw := bytes.Repeat(fixture, (size+len(fixture)-1)/len(fixture))[:size]
		for _, method := range []string{"ReadAll", "ContentLength"} {
			b.Run(fmt.Sprintf("%d/%s", size, method), func(b *testing.B) {
				b.SetBytes(int64(len(raw)))
				b.ReportAllocs()
				for b.Loop() {
					res := &http.Response{Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw))}
					var err error
					if method == "ReadAll" {
						_, err = io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
					} else {
						_, err = readResponse(res)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
