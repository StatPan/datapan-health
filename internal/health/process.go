package health

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CLIProcess invokes the documented one-shot CLI surface. Only explicitly
// named provider credential variables cross into this process; Gatus/archive
// settings are intentionally absent from its environment.
type CLIProcess struct {
	Path        string
	Environment []string
}

func (p CLIProcess) Run(ctx context.Context, _ Canary, entry CatalogEntry, output string) error {
	args := cliHealthArgs(entry, output)
	cmd := exec.CommandContext(ctx, p.Path, args...)
	cmd.Env = selectEnvironment(p.Environment)
	// CLI output may include provider diagnostics. Never stream it to scheduler
	// logs; the schema-validated receipt is the only accepted result.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run()
}

// cliHealthArgs keeps the process boundary aligned with the reviewed Registry
// execution policy. The CLI enforces this timeout while creating its redacted
// receipt; the scheduler supplies the enclosing process deadline.
func cliHealthArgs(entry CatalogEntry, output string) []string {
	timeout := time.Duration(entry.Execution.TimeoutCeilingMS) * time.Millisecond
	return []string{"verify", "--ref", entry.Aliases.DatasetID, "--operation", entry.Aliases.OperationName, "--health", "--timeout", timeout.String(), "--output", output, "--json"}
}

// AdapterProcess is the existing health-runner receipt adapter. The scheduler
// has no direct Gatus or archive implementation and therefore cannot change
// its public projection.
type AdapterProcess struct {
	Path string
	Env  []string
}

func (p AdapterProcess) Deliver(ctx context.Context, receiptPath string) error {
	cmd := exec.CommandContext(ctx, p.Path, "-receipt", receiptPath)
	cmd.Env = selectEnvironment(p.Env)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run()
}

func selectEnvironment(names []string) []string {
	values := make([]string, 0, len(names)+2)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || strings.Contains(name, "=") {
			continue
		}
		if value, ok := os.LookupEnv(name); ok {
			values = append(values, name+"="+value)
		}
	}
	// A predictable PATH is needed only for executable lookup; all secret
	// values remain opt-in above.
	values = append(values, "PATH=/usr/local/bin:/usr/bin:/bin")
	return values
}
