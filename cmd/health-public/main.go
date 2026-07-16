package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	listen := flag.String("listen", env("PUBLIC_STATUS_LISTEN", ":8082"), "private listener for the public status adapter")
	gatusStatusURL := flag.String("gatus-status-url", env("GATUS_STATUS_URL", "http://gatus:8080/api/v1/endpoints/statuses"), "private Gatus summary URL")
	canaryPath := flag.String("canaries", env("CANARY_CONFIG", "config/canaries.json"), "reviewed public canary identity map")
	originList := flag.String("allowed-origins", os.Getenv("PUBLIC_STATUS_ALLOWED_ORIGINS"), "comma-separated exact HTTPS browser origins")
	flag.Parse()

	canaries, err := health.LoadCanaryConfig(*canaryPath)
	if err != nil {
		fatal()
	}
	source, err := health.NewGatusPublicStatusSource(*gatusStatusURL, canaries, 5*time.Second)
	if err != nil {
		fatal()
	}
	origins := splitOrigins(*originList)
	handler, err := health.NewPublicStatusHandler(source, origins)
	if err != nil {
		fatal()
	}

	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal()
	}
}

func splitOrigins(value string) []string {
	parts := strings.Split(value, ",")
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			origins = append(origins, trimmed)
		}
	}
	return origins
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func fatal() {
	fmt.Fprintln(os.Stderr, "public status service failed")
	os.Exit(1)
}
