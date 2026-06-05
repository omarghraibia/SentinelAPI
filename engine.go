// Package analysis provides high-throughput, low-latency threat detection.
// Copyright (c) 2026 omarghraibia. MIT License.
package analysis

import (
	"context"
	"errors"
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var (
	ErrRequestTooLarge = errors.New("request payload exceeds maximum analysis threshold")
	ErrEngineTimeout   = errors.New("analysis engine timed out")
)

const MaxInspectBytes = 128 * 1024 // 128KB max WAF memory buffer limit per request

var payloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, MaxInspectBytes)
		return &b
	},
}

// RequestCtx encapsulates the zero-copy request data needed for analysis.
type RequestCtx struct {
	ClientIP  string
	UserAgent string
	Path      string
	Method    string
	Body      io.Reader // Streamed payload to avoid memory exhaustion

	// Internal fields for zero-allocation buffered reads
	rawBuf    *[]byte
	bytesRead int
	readPos   int
}

// Read implements io.Reader for the buffered payload without heap allocations.
func (r *RequestCtx) Read(p []byte) (int, error) {
	if r.rawBuf == nil || r.readPos >= r.bytesRead {
		return 0, io.EOF
	}
	n := copy(p, (*r.rawBuf)[r.readPos:r.bytesRead])
	r.readPos += n
	return n, nil
}

// Seek implements io.Seeker to allow multiple detectors to rewind the buffer.
func (r *RequestCtx) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekStart {
		r.readPos = int(offset)
		return offset, nil
	}
	return int64(r.readPos), nil
}

// LoadBody reads the payload for inspection up to MaxInspectBytes.
// It returns a reconstructed io.Reader that the HTTP handler can use to forward 
// the entire original payload upstream.
func (r *RequestCtx) LoadBody(body io.Reader) (io.Reader, error) {
	if body == nil {
		return nil, nil
	}

	r.rawBuf = payloadPool.Get().(*[]byte)
	n, err := io.ReadFull(body, (*r.rawBuf)[:MaxInspectBytes])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	r.bytesRead = n
	r.readPos = 0
	r.Body = r // RequestCtx itself acts as the rewindable io.ReadSeeker

	// Return a MultiReader stitching the buffered bytes with any remaining unread bytes
	return io.MultiReader(bytes.NewReader((*r.rawBuf)[:n]), body), nil
}

// Detector defines the contract for pluggable threat analysis rules.
type Detector interface {
	Name() string
	Analyze(ctx context.Context, req *RequestCtx) (int, []string)
}

// Engine orchestrates thread-safe, lock-free execution of detectors.
type Engine struct {
	// atomic.Pointer allows lock-free hot-reloading of detectors
	detectors atomic.Pointer[[]Detector]
	
	// Telemetry
	tracer  trace.Tracer
	latency metric.Float64Histogram
	
	// Object pool for allocating context wrappers to avoid GC pressure
	ctxPool *sync.Pool
}

// NewEngine initializes a production-ready ThreatEngine.
func NewEngine(initialDetectors []Detector) *Engine {
	meter := otel.Meter("sentinelapi/analysis")
	latency, _ := meter.Float64Histogram(
		"threat_engine.latency",
		metric.WithDescription("Latency of the threat detection engine"),
		metric.WithUnit("ms"),
	)

	e := &Engine{
		tracer:  otel.Tracer("sentinelapi/analysis"),
		latency: latency,
		ctxPool: &sync.Pool{
			New: func() any { return new(RequestCtx) },
		},
	}
	e.UpdateDetectors(initialDetectors)
	return e
}

// UpdateDetectors replaces the active ruleset safely with zero downtime.
func (e *Engine) UpdateDetectors(newDetectors []Detector) {
	e.detectors.Store(&newDetectors)
}

// Analyze evaluates a request against all loaded detectors concurrently if needed,
// but optimized for fast-path sequential execution to avoid goroutine overhead for fast rules.
func (e *Engine) Analyze(ctx context.Context, req *RequestCtx) (int, []string, error) {
	start := time.Now()
	ctx, span := e.tracer.Start(ctx, "ThreatEngine.Analyze")
	defer span.End()

	// Defensive: ensure context cancellation is respected
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}

	// Safe default
	maxScore := 0
	var allFlags []string

	detectors := *e.detectors.Load()

	// Iterate through detectors. For ultra-low latency, we avoid spawning
	// goroutines here unless the specific detector is known to be blocking/heavy.
	for _, d := range detectors {
		// Rewind the stream to 0 so the next detector can read the same payload
		if seeker, ok := req.Body.(io.Seeker); ok {
			_, _ = seeker.Seek(0, io.SeekStart)
		}

		// Pass the root context. Creating context.WithTimeout in a hot loop triggers severe heap allocations.
		score, flags := d.Analyze(ctx, req)
		
		if score > maxScore {
			maxScore = score
		}
		if len(flags) > 0 {
			allFlags = append(allFlags, flags...)
		}

		// Early exit threshold: If highly malicious, stop processing to save CPU.
		if maxScore >= 100 {
			break
		}
	}

	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	e.latency.Record(ctx, elapsed, metric.WithAttributes(
		attribute.Int("threat_score", maxScore),
	))

	return maxScore, allFlags, nil
}

// AcquireRequestCtx retrieves a zero-allocated struct from the pool.
func (e *Engine) AcquireRequestCtx() *RequestCtx {
	return e.ctxPool.Get().(*RequestCtx)
}

// ReleaseRequestCtx sanitizes and returns the struct to the pool.
func (e *Engine) ReleaseRequestCtx(req *RequestCtx) {
	req.ClientIP = ""
	req.UserAgent = ""
	req.Path = ""
	req.Method = ""
	req.Body = nil // prevent memory leaks of the underlying slice
	
	if req.rawBuf != nil {
		payloadPool.Put(req.rawBuf)
		req.rawBuf = nil
	}
	req.bytesRead = 0
	req.readPos = 0

	e.ctxPool.Put(req)
}