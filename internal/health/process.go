package health

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
)

// CLIProcess invokes the documented one-shot CLI surface. Only explicitly
// named provider credential variables cross into this process; Gatus/archive
// settings are intentionally absent from its environment.
type CLIProcess struct {
	Path        string
	Environment []string
}

func (p CLIProcess) Run(ctx context.Context, _ Canary, entry CatalogEntry, output string) error {
	args := []string{"verify", "--ref", entry.Aliases.DatasetID, "--operation", entry.Aliases.OperationName, "--health", "--output", output, "--json"}
	cmd := exec.CommandContext(ctx, p.Path, args...)
	cmd.Env = selectEnvironment(p.Environment)
	// CLI output may include provider diagnostics. Never stream it to scheduler
	// logs; the schema-validated receipt is the only accepted result.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run()
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
