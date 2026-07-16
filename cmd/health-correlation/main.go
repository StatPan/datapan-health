package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	rulePath := flag.String("rule", "config/correlation/provider-outage.v1.json", "versioned correlation rule")
	canaryPath := flag.String("canaries", "config/canaries.json", "accepted canary configuration")
	replayPath := flag.String("replay", "", "offline redacted replay input")
	flag.Parse()
	if *replayPath == "" {
		fatal()
	}
	rule, err := health.LoadCorrelationRule(*rulePath)
	if err != nil {
		fatal()
	}
	canaries, err := health.LoadCanaryConfig(*canaryPath)
	if err != nil {
		fatal()
	}
	file, err := os.Open(*replayPath)
	if err != nil {
		fatal()
	}
	defer file.Close()
	replay, err := health.DecodeCorrelationReplay(file)
	if err != nil {
		fatal()
	}
	receipt, err := health.CorrelateProviderOutage(rule, canaries, replay)
	if err != nil {
		fatal()
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(receipt); err != nil {
		fatal()
	}
}

func fatal() {
	fmt.Fprintln(os.Stderr, "health correlation replay failed")
	os.Exit(1)
}
