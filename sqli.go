// Package analysis provides high-throughput, low-latency threat detection.
// Copyright (c) 2026 omarghraibia. MIT License.
package analysis

import (
	"context"
	"io"
	"sync"
)

// bufferPool ensures zero-allocation during chunked body reads.
var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096) // 4KB chunks, aligned with typical OS page/L2 cache sizes
		return &b
	},
}

// TrieNode represents a single character node in the Aho-Corasick automaton.
type TrieNode struct {
	children [256]*TrieNode // Replaced map with array for true O(1) direct memory access
	fail     *TrieNode
	outputs  []string // matched SQLi signatures ending at this node
}

// AhoCorasick holds the root of the state machine.
type AhoCorasick struct {
	root *TrieNode
}

// NewAhoCorasick compiles a list of signatures into a deterministic finite automaton.
func NewAhoCorasick(keywords []string) *AhoCorasick {
	ac := &AhoCorasick{
		root: &TrieNode{},
	}

	// Step 1: Build the standard Trie
	for _, kw := range keywords {
		curr := ac.root
		for i := 0; i < len(kw); i++ {
			// We enforce uppercase during compilation for case-insensitive matching
			c := toUpper(kw[i])
			if curr.children[c] == nil {
				curr.children[c] = &TrieNode{}
			}
			curr = curr.children[c]
		}
		curr.outputs = append(curr.outputs, kw)
	}

	// Step 2: Build failure links using Breadth-First Search (BFS)
	ac.buildFailures()

	return ac
}

func (ac *AhoCorasick) buildFailures() {
	queue := []*TrieNode{}

	// Root's children fail back to root
	for i := 0; i < 256; i++ {
		child := ac.root.children[i]
		if child == nil { continue }
		child.fail = ac.root
		queue = append(queue, child)
	}

	// Process nodes level by level
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for c := 0; c < 256; c++ {
			child := curr.children[c]
			if child == nil { continue }
			queue = append(queue, child)

			// Follow fail links of the parent to find the longest proper suffix
			failNode := curr.fail
			for failNode != nil && failNode.children[c] == nil {
				failNode = failNode.fail
			}

			if failNode == nil {
				child.fail = ac.root
			} else {
				child.fail = failNode.children[c]
				
				// Merge outputs from the fail node to catch overlapping signatures
				if len(child.fail.outputs) > 0 {
					merged := make([]string, 0, len(child.outputs)+len(child.fail.outputs))
					merged = append(merged, child.outputs...)
					merged = append(merged, child.fail.outputs...)
					child.outputs = merged
				}
			}
		}
	}
}

// SQLiDetector implements the Detector interface using Aho-Corasick.
type SQLiDetector struct {
	machine *AhoCorasick
}

// NewSQLiDetector initializes the SQL injection scanner with common attack vectors.
func NewSQLiDetector() *SQLiDetector {
	// In a real-world scenario, these would be loaded from a config or database.
	signatures := []string{
		"UNION SELECT",
		"UNION ALL SELECT",
		"DROP TABLE",
		"OR 1=1",
		"SLEEP(",
		"WAITFOR DELAY",
		"INFORMATION_SCHEMA",
		"XP_CMDSHELL",
		"--",
		"/*",
	}
	return &SQLiDetector{
		machine: NewAhoCorasick(signatures),
	}
}

// Name returns the identifier of the detector.
func (d *SQLiDetector) Name() string {
	return "SQLi_AhoCorasick_DFA"
}

// Analyze streams the zero-copy request body through the state machine.
func (d *SQLiDetector) Analyze(ctx context.Context, req *RequestCtx) (int, []string) {
	var flags []string
	score := 0

	if req.Body == nil {
		return score, flags
	}

	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	curr := d.machine.root
	for {
		// Respect context cancellation (e.g., global timeout or client disconnect) per chunk
		if err := ctx.Err(); err != nil {
			break
		}

		n, err := req.Body.Read(buf)
		for i := 0; i < n; i++ {
			// Convert to uppercase on the fly: NO memory allocations!
			c := toUpper(buf[i])

			// Traverse failure links if character doesn't match
			for curr != nil && curr != d.machine.root && curr.children[c] == nil {
				curr = curr.fail
			}

			if curr.children[c] != nil {
				curr = curr.children[c]
			} else {
				curr = d.machine.root
			}

			// If we hit an output state, we found a malicious signature
			if len(curr.outputs) > 0 {
				if len(flags) < 5 { // Bound the slice growth to prevent Algorithmic DoS
					flags = append(flags, curr.outputs...)
				}
				score = 100 // Immediate high threat score for SQLi
			}
		}

		if err != nil {
			break // Handles io.EOF or client read disconnects
		}

		// Early exit threshold: stop scanning huge files if we've already flagged it
		if score >= 100 {
			break
		}
	}

	return score, flags
}

// toUpper is an inline utility for ASCII fast-path uppercase conversion.
func toUpper(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - 32
	}
	return b
}