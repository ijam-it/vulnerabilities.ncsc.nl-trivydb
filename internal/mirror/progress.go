package mirror

import (
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

type syncProgress struct {
	out                               io.Writer
	width                             func() int // Non-nil only for an interactive terminal.
	active                            bool
	receivedBytes                     int64
	fetched                           int
	fetchTime, processTime, writeTime time.Duration
}

func newSyncProgress() *syncProgress {
	p := &syncProgress{out: log.Writer()}
	if f, ok := p.out.(*os.File); ok && os.Getenv("TERM") != "dumb" && terminalWidth(f) > 0 {
		p.width = func() int { return terminalWidth(f) }
	}
	return p
}

func (p *syncProgress) draw(line string) {
	// Leave the last column empty to avoid wrapping into a second terminal row.
	width := max(1, p.width()-1)
	if len(line) > width {
		line = line[:width]
	}
	fmt.Fprintf(p.out, "\r\x1b[2K%s", line)
	p.active = true
}

func (p *syncProgress) phase(format string, args ...any) {
	if p.width == nil {
		log.Printf(format, args...)
		return
	}
	p.draw(fmt.Sprintf(format, args...))
}

func (p *syncProgress) message(format string, args ...any) {
	if p.width == nil {
		log.Printf(format, args...)
		return
	}
	if p.active {
		fmt.Fprint(p.out, "\r\x1b[2K")
		p.active = false
	}
	// Messages (especially failures) retain their full text, even if they wrap.
	fmt.Fprintf(p.out, format+"\n", args...)
}

func (p *syncProgress) update(s Snapshot, reused int, elapsed time.Duration) {
	transfer := ""
	if elapsed > 0 && p.receivedBytes > 0 {
		transfer = fmt.Sprintf("%.1f MiB/s", float64(p.receivedBytes)/(1<<20)/elapsed.Seconds())
	}
	if p.width == nil {
		line := formatProgress(s, reused, elapsed)
		if transfer != "" {
			line += "; " + transfer
			line += fmt.Sprintf("; fetch=%s/doc process=%s/doc writes=%s", (p.fetchTime / time.Duration(p.fetched)).Round(time.Millisecond),
				(p.processTime / time.Duration(p.fetched)).Round(time.Millisecond), p.writeTime.Round(time.Millisecond))
		}
		log.Print(line)
		return
	}
	p.draw(formatTerminalProgressWithTransfer(s, reused, elapsed, max(1, p.width()-1), transfer))
}

func (p *syncProgress) finish() {
	if p.active {
		fmt.Fprintln(p.out)
		p.active = false
	}
}

type progressMeasurement struct {
	downloaded, remaining int
	percent, rate         float64
	eta                   time.Duration
	etaKnown              bool
}

func measureProgress(s Snapshot, reused int, elapsed time.Duration) progressMeasurement {
	p := progressMeasurement{downloaded: s.Available - reused, remaining: s.Selected - s.Available - s.Failed}
	if s.Selected > 0 {
		p.percent = 100 * float64(s.Available) / float64(s.Selected)
	}
	if elapsed > 0 {
		p.rate = float64(p.downloaded) / elapsed.Seconds()
	}
	p.etaKnown = p.remaining == 0 || p.rate > 0
	if p.remaining > 0 && p.rate > 0 {
		p.eta = time.Duration(math.Ceil(float64(p.remaining)/p.rate)) * time.Second
	}
	return p
}

func formatTerminalProgress(s Snapshot, reused int, elapsed time.Duration, width int) string {
	return formatTerminalProgressWithTransfer(s, reused, elapsed, width, "")
}

func formatTerminalProgressWithTransfer(s Snapshot, reused int, elapsed time.Duration, width int, transfer string) string {
	p := measureProgress(s, reused, elapsed)
	eta := "--"
	if p.etaKnown {
		eta = compactDuration(p.eta)
	}
	count := fmt.Sprintf("%s/%s", comma(s.Available), comma(s.Selected))
	failure := ""
	if s.Failed > 0 {
		failure = fmt.Sprintf(" | %s failed", comma(s.Failed))
	}
	// Drop secondary details as the terminal narrows, keeping the ETA and any
	// failure count ahead of the bar and throughput in the space budget.
	candidates := []string{
		fmt.Sprintf("%5.1f%% | %s | %.1f/s | ETA %s%s | +%s in %s", p.percent, count, p.rate, eta, failure, comma(p.downloaded), compactDuration(elapsed)),
		fmt.Sprintf("%5.1f%% | %s | %.1f/s | ETA %s%s", p.percent, count, p.rate, eta, failure),
		fmt.Sprintf("%5.1f%% | %s | ETA %s%s", p.percent, count, eta, failure),
		fmt.Sprintf("%.1f%% | ETA %s%s", p.percent, eta, failure),
	}
	if transfer != "" {
		candidates = append([]string{
			fmt.Sprintf("%5.1f%% | %s | %.1f/s | %s | ETA %s%s | +%s in %s", p.percent, count, p.rate, transfer, eta, failure, comma(p.downloaded), compactDuration(elapsed)),
			fmt.Sprintf("%5.1f%% | %s | %.1f/s | %s | ETA %s%s", p.percent, count, p.rate, transfer, eta, failure),
		}, candidates...)
	}
	for _, text := range candidates {
		barWidth := min(24, width-len(text)-3)
		if barWidth >= 8 {
			filled := min(barWidth, max(0, int(float64(barWidth)*p.percent/100)))
			bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)
			return "[" + bar + "] " + text
		}
	}
	text := candidates[len(candidates)-1]
	return text[:min(len(text), max(0, width))]
}

func comma(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func compactDuration(d time.Duration) string {
	if d >= time.Hour {
		return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int(d/time.Minute)%60)
	}
	if d >= time.Minute {
		return fmt.Sprintf("%dm%02ds", int(d/time.Minute), int(d/time.Second)%60)
	}
	return fmt.Sprintf("%ds", int(d/time.Second))
}
