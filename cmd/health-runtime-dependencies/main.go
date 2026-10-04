package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/StatPan/datapan-health/internal/runtimebundle"
)

func main() {
	lockPath := flag.String("lock", "config/runtime-dependencies.json", "immutable dependency lock")
	directory := flag.String("directory", "/opt/datapan-cli", "minimal CLI install directory")
	arch := flag.String("arch", runtime.GOARCH, "Linux dependency architecture")
	verify := flag.Bool("verify-local", false, "verify installed files without network access")
	prove := flag.Bool("prove-cli", false, "prove declared HTTP execution in an isolated image against synthetic loopback only")
	flag.Parse()
	lock, err := runtimebundle.ReadLock(*lockPath)
	if err == nil {
		if *verify {
			err = runtimebundle.VerifyLocal(lock, *arch, *directory)
			if err == nil && *prove {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				err = runtimebundle.ProveCLI(ctx, lock, *directory)
			}
		} else {
			if *prove {
				fmt.Fprintln(os.Stderr, "CLI proof requires verify-local")
				os.Exit(1)
			}
			client := &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
				host := req.URL.Hostname()
				if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Port() != "" || !(host == "github.com" || host == "release-assets.githubusercontent.com" || host == "huggingface.co" || strings.HasSuffix(host, ".huggingface.co") || strings.HasSuffix(host, ".hf.co")) {
					return fmt.Errorf("dependency redirect rejected")
				}
				return nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			err = runtimebundle.Install(ctx, client, lock, *arch, *directory)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("immutable Health runtime dependencies verified")
}
