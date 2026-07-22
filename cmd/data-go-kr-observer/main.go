// data-go-kr-observer is the fixed Health-owned child executable for bounded
// data.go.kr observation. It intentionally has no flags, URL input, provider
// selector, or output channel. #37 establishes the immutable process and
// redaction boundary only; a later, separately authorized deployment binding
// is required before any live transport can be enabled.
package main

import (
	"os"
	"regexp"
)

var (
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	countPattern  = regexp.MustCompile(`^(?:[1-9]|[1-9][0-9]|100)$`)
	indexPattern  = regexp.MustCompile(`^[0-7]$`)
)

func main() {
	index := os.Getenv("DATAPAN_HEALTH_OBSERVATION_SHARD_INDEX")
	digest := os.Getenv("DATAPAN_HEALTH_OBSERVATION_SHARD_DIGEST")
	count := os.Getenv("DATAPAN_HEALTH_OBSERVATION_OPERATION_COUNT")
	if !indexPattern.MatchString(index) || !digestPattern.MatchString(digest) || !countPattern.MatchString(count) {
		os.Exit(76) // typed unknown; no diagnostic text is emitted.
	}
	// Deliberately no provider request in this task. The binary consumes only
	// the sealed shard binding and fails closed as unknown until #33 has a
	// separately approved immutable deployment and live-observation authority.
	os.Exit(76)
}
