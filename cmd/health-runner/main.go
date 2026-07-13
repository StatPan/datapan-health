package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	var receiptPath, gatusURL, token, archivePath, canaryPath string
	flag.StringVar(&receiptPath, "receipt", "", "path to a datapan.health-probe.v1 receipt")
	flag.StringVar(&gatusURL, "gatus-url", env("GATUS_URL", "http://gatus:8080"), "Gatus base URL")
	flag.StringVar(&token, "token", os.Getenv("GATUS_TOKEN"), "Gatus external-endpoint token")
	flag.StringVar(&archivePath, "archive", env("RECEIPT_ARCHIVE", "data/receipts.jsonl"), "local redacted receipt archive")
	flag.StringVar(&canaryPath, "canaries", env("CANARY_CONFIG", "config/canaries.json"), "public canary identity mapping")
	flag.Parse()

	if receiptPath == "" || token == "" {
		fmt.Fprintln(os.Stderr, "receipt and token are required")
		os.Exit(2)
	}
	receipt, err := health.ReadReceipt(receiptPath)
	if err != nil {
		fail(err)
	}
	canaries, err := health.LoadCanaryConfig(canaryPath)
	if err != nil {
		fail(fmt.Errorf("load canaries: %w", err))
	}
	endpointKey, err := canaries.Resolve(receipt)
	if err != nil {
		fail(err)
	}
	sink := health.NewLocalSink(archivePath)
	if err := sink.Store(context.Background(), receipt); err != nil {
		fail(fmt.Errorf("archive receipt: %w", err))
	}
	pusher := health.NewGatusPusher(gatusURL, token, 10*time.Second)
	if err := pusher.Push(context.Background(), health.Summarize(receipt, endpointKey)); err != nil {
		fail(fmt.Errorf("push summary: %w", err))
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
