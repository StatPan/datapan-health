package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	actualCLIContainerIP          = "45.77.0.4"
	actualCLIContainerMemoryLimit = int64(1 << 30)
)

type actualCLIContainerMonitor struct {
	container string
	stop      chan struct{}
	done      chan struct{}
	mu        sync.Mutex
	peakBytes uint64
	samples   int
}

func startActualCLIContainers(t *testing.T, root, binaryPath, binarySHA, providerBinary, providerCA, providerCertificate, providerKey, providerRoutes, planRoot, credentialPath, receiptRoot string, gatusConfig []byte, token string) (networkName, cliContainer, gatusURL, metricsURL string, monitor *actualCLIContainerMonitor) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	networkName = "health95-internal-" + stamp
	providerContainer := "health95-provider-" + stamp
	gatusContainer := "health95-gatus-" + stamp
	cliContainer = "health95-cli-" + stamp
	imageName := "health95-cli-fixture:" + stamp
	providerImageName := "health95-provider-fixture:" + stamp
	cliUser := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	if os.Getuid() <= 0 || os.Getgid() < 0 {
		t.Fatal("the no-egress CLI sandbox requires a non-root host UID and GID")
	}
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if monitor != nil {
			monitor.Stop()
		}
		for _, name := range []string{cliContainer, gatusContainer, providerContainer} {
			_ = exec.CommandContext(cleanupCtx, "docker", "rm", "--force", name).Run()
		}
		_ = exec.CommandContext(cleanupCtx, "docker", "network", "rm", networkName).Run()
		_ = exec.CommandContext(cleanupCtx, "docker", "image", "rm", imageName).Run()
		_ = exec.CommandContext(cleanupCtx, "docker", "image", "rm", providerImageName).Run()
	}
	t.Cleanup(cleanup)

	binaryBytes, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal("could not re-read the freshly compiled exact-source CLI binary")
	}
	sum := sha256.Sum256(binaryBytes)
	if hex.EncodeToString(sum[:]) != binarySHA {
		t.Fatal("fresh CLI binary changed after its immutable runtime digest was calculated")
	}
	imageRoot := filepath.Join(root, "cli-fixture-image")
	if err := os.MkdirAll(imageRoot, 0o700); err != nil {
		t.Fatal("could not prepare the static no-egress CLI image context")
	}
	stagedCLI := filepath.Join(imageRoot, "datapan-cli")
	if err := os.WriteFile(stagedCLI, binaryBytes, 0o444); err != nil {
		t.Fatal("could not stage the exact CLI bytes as an immutable fixture mount")
	}
	stagedCLIBytes, err := os.ReadFile(stagedCLI)
	if err != nil || digest(stagedCLIBytes) != binarySHA {
		t.Fatal("readonly CLI fixture mount bytes do not match the runtime-locked source build")
	}
	launcher := filepath.Join(imageRoot, "launcher")
	buildLauncher := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", launcher, "./internal/health/testdata/actual-cli-sandbox")
	buildLauncher.Dir = "../.."
	buildLauncher.Env = offlineGoBuildEnv()
	if output, err := buildLauncher.CombinedOutput(); err != nil {
		t.Fatalf("could not build the bounded CLI-child supervisor (exit=%v, output_bytes=%d)", err, len(output))
	}
	if err := os.Chmod(launcher, 0o555); err != nil {
		t.Fatal("could not make the no-egress child supervisor executable")
	}
	if err := os.Chmod(stagedCLI, 0o555); err != nil {
		t.Fatal("could not make the exact CLI binary executable in the fixture mount")
	}
	dockerfile := []byte("FROM scratch\nCOPY launcher /launcher\nUSER " + cliUser + "\nENTRYPOINT [\"/launcher\"]\nCMD [\"pause\"]\n")
	if err := os.WriteFile(filepath.Join(imageRoot, "Dockerfile"), dockerfile, 0o444); err != nil {
		t.Fatal("could not write the static local-fixture Dockerfile")
	}
	buildImage := exec.CommandContext(ctx, "docker", "build", "--network=none", "--pull=false", "--tag", imageName, "--file", filepath.Join(imageRoot, "Dockerfile"), imageRoot)
	if output, err := buildImage.CombinedOutput(); err != nil {
		t.Fatalf("could not build the fixture image without network access (exit=%v, output_bytes=%d)", err, len(output))
	}
	providerImageRoot := filepath.Join(root, "provider-fixture-image")
	providerTLSRoot := filepath.Join(providerImageRoot, "tls")
	if err := os.MkdirAll(providerTLSRoot, 0o700); err != nil {
		t.Fatal("could not prepare the synthetic TLS provider image")
	}
	for target, contents := range map[string][]byte{
		filepath.Join(providerImageRoot, "provider"):    mustReadFile(t, providerBinary),
		filepath.Join(providerTLSRoot, "server.pem"):    mustReadFile(t, providerCertificate),
		filepath.Join(providerTLSRoot, "server.key"):    mustReadFile(t, providerKey),
		filepath.Join(providerImageRoot, "routes.json"): mustReadFile(t, providerRoutes),
	} {
		mode := os.FileMode(0o555)
		if strings.HasSuffix(target, ".pem") || strings.HasSuffix(target, ".key") {
			mode = 0o444
		}
		if err := os.WriteFile(target, contents, mode); err != nil {
			t.Fatal("could not stage synthetic provider TLS files")
		}
	}
	providerDockerfile := []byte("FROM scratch\nCOPY provider /provider\nCOPY tls /tls\nCOPY routes.json /routes.json\nUSER 1000:1000\nENTRYPOINT [\"/provider\",\"--tls-cert\",\"/tls/server.pem\",\"--tls-key\",\"/tls/server.key\",\"--routes\",\"/routes.json\"]\n")
	if err := os.WriteFile(filepath.Join(providerImageRoot, "Dockerfile"), providerDockerfile, 0o444); err != nil {
		t.Fatal("could not write the synthetic provider Dockerfile")
	}
	buildProviderImage := exec.CommandContext(ctx, "docker", "build", "--network=none", "--pull=false", "--tag", providerImageName, "--file", filepath.Join(providerImageRoot, "Dockerfile"), providerImageRoot)
	if output, err := buildProviderImage.CombinedOutput(); err != nil {
		t.Fatalf("could not build the synthetic HTTPS provider without network access (exit=%v, output_bytes=%d)", err, len(output))
	}

	ensureActualCLIProviderSubnetAvailable(t, ctx)
	if output, err := exec.CommandContext(ctx, "docker", "network", "create", "--internal", "--subnet", actualCLIProviderSubnet, networkName).CombinedOutput(); err != nil {
		t.Fatalf("could not create an isolated internal Docker network (exit=%v, output_bytes=%d)", err, len(output))
	}
	networkInfo, err := exec.CommandContext(ctx, "docker", "network", "inspect", "--format", "{{.Internal}} {{range .IPAM.Config}}{{.Subnet}}{{end}}", networkName).Output()
	if err != nil || strings.TrimSpace(string(networkInfo)) != "true "+actualCLIProviderSubnet {
		t.Fatal("test network is not the exact internal-only fixture subnet")
	}

	startContainer := func(name, image, ip, user, memory, cpus string, pids int, tmpfs string, args ...string) {
		t.Helper()
		base := []string{"run", "--detach", "--rm", "--name", name, "--network", networkName, "--ip", ip,
			"--read-only", "--user", user, "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
			"--pids-limit=" + strconv.Itoa(pids), "--memory=" + memory, "--cpus=" + cpus, "--tmpfs", tmpfs}
		commandArgs := append(base, args...)
		commandArgs = append(commandArgs, image)
		command := exec.CommandContext(ctx, "docker", commandArgs...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("could not start bounded fixture container %s (exit=%v, output_bytes=%d)", name, err, len(output))
		}
	}
	startContainer(providerContainer, providerImageName, actualCLIProviderIP, "1000:1000", "64m", "1", 32, "/tmp:rw,noexec,nosuid,size=8m,uid=1000,gid=1000")
	metricsURL = "https://" + net.JoinHostPort(actualCLIProviderIP, "8080")

	gatusConfigPath := filepath.Join(root, "actual-cli-gatus.yaml")
	if err := os.WriteFile(gatusConfigPath, gatusConfig, 0o444); err != nil {
		t.Fatal("could not stage the exact generated Gatus configuration")
	}
	startContainer(gatusContainer, actualCLIGatusImage, actualCLIGatusIP, "1000:1000", "512m", "2", 64, "/tmp:rw,noexec,nosuid,size=32m,uid=1000,gid=1000", "--tmpfs", "/data:rw,noexec,nosuid,size=64m,uid=1000,gid=1000", "--mount", "type=bind,source="+gatusConfigPath+",target=/config/config.yaml,readonly", "--env", "GATUS_TOKEN="+token)
	gatusURL = "http://" + net.JoinHostPort(actualCLIGatusIP, "8080")

	startCLI := []string{
		"run", "--detach", "--rm", "--name", cliContainer, "--network", networkName, "--ip", actualCLIContainerIP,
		"--read-only", "--user", cliUser, "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
		"--pids-limit=256", "--memory=" + strconv.FormatInt(actualCLIContainerMemoryLimit/(1<<20), 10) + "m", "--cpus=4",
		"--tmpfs", fmt.Sprintf("/tmp:rw,noexec,nosuid,size=64m,uid=%d,gid=%d", os.Getuid(), os.Getgid()), "--workdir", planRoot,
		"--mount", "type=bind,source=" + stagedCLI + ",target=/datapan-cli,readonly",
		"--mount", "type=bind,source=" + planRoot + ",target=" + planRoot + ",readonly",
		"--mount", "type=bind,source=" + receiptRoot + ",target=" + receiptRoot,
		"--mount", "type=bind,source=" + providerCA + ",target=/fixture-ca.pem,readonly",
		"--entrypoint", "/launcher", imageName, "pause",
	}
	if output, err := exec.CommandContext(ctx, "docker", startCLI...).CombinedOutput(); err != nil {
		t.Fatalf("could not start the bounded no-egress CLI sandbox (exit=%v, output_bytes=%d)", err, len(output))
	}
	verifyActualCLIIsolation(t, ctx, networkName, providerContainer, gatusContainer, cliContainer, actualCLIProviderIP, actualCLIGatusIP, stagedCLI, planRoot, receiptRoot, providerCA, gatusConfigPath, cliUser)
	if !waitActualCLIGatusReady(ctx, gatusURL) {
		t.Fatal("pinned Gatus did not load the generated local full-population configuration")
	}
	monitor = &actualCLIContainerMonitor{container: cliContainer, stop: make(chan struct{}), done: make(chan struct{})}
	go monitor.run()
	return networkName, cliContainer, gatusURL, metricsURL, monitor
}

func offlineGoBuildEnv() []string {
	return []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local"}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatal("required local fixture binary is unavailable")
	}
	return data
}

func verifyActualCLIIsolation(t *testing.T, ctx context.Context, network, provider, gatus, cli, providerIP, gatusIP, binaryPath, planRoot, receiptRoot, caPath, gatusConfigPath, cliUser string) {
	t.Helper()
	type inspectedContainer struct {
		Config struct {
			Env  []string `json:"Env"`
			Tty  bool     `json:"Tty"`
			User string   `json:"User"`
		} `json:"Config"`
		HostConfig struct {
			NetworkMode  string            `json:"NetworkMode"`
			ReadonlyRoot bool              `json:"ReadonlyRootfs"`
			Privileged   bool              `json:"Privileged"`
			CapDrop      []string          `json:"CapDrop"`
			SecurityOpt  []string          `json:"SecurityOpt"`
			PidsLimit    int64             `json:"PidsLimit"`
			Memory       int64             `json:"Memory"`
			NanoCPUs     int64             `json:"NanoCpus"`
			Tmpfs        map[string]string `json:"Tmpfs"`
			PortBindings map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	for name, wantIP := range map[string]string{provider: providerIP, gatus: gatusIP, cli: actualCLIContainerIP} {
		output, err := exec.CommandContext(ctx, "docker", "inspect", name).Output()
		var values []inspectedContainer
		if err != nil || json.Unmarshal(output, &values) != nil || len(values) != 1 {
			t.Fatal("could not verify fixture container isolation settings")
		}
		item := values[0]
		networkAttachment, found := item.NetworkSettings.Networks[network]
		if !found || len(item.NetworkSettings.Networks) != 1 || networkAttachment.IPAddress != wantIP || item.HostConfig.NetworkMode != network {
			t.Fatal("fixture container has an unexpected network or destination address")
		}
		wantUser := "1000:1000"
		wantMemory := int64(64 << 20)
		wantPids := int64(32)
		wantNanoCPUs := int64(1_000_000_000)
		wantTmpfs := map[string]string{"/tmp": "rw,noexec,nosuid,size=8m,uid=1000,gid=1000"}
		wantBinds := map[string]struct {
			source   string
			readOnly bool
		}{}
		if name == cli {
			wantUser = cliUser
			wantMemory = actualCLIContainerMemoryLimit
			wantPids = 256
			wantNanoCPUs = 4_000_000_000
			wantTmpfs = map[string]string{"/tmp": fmt.Sprintf("rw,noexec,nosuid,size=64m,uid=%d,gid=%d", os.Getuid(), os.Getgid())}
			wantBinds = map[string]struct {
				source   string
				readOnly bool
			}{
				"/datapan-cli":    {source: binaryPath, readOnly: true},
				planRoot:          {source: planRoot, readOnly: true},
				receiptRoot:       {source: receiptRoot, readOnly: false},
				"/fixture-ca.pem": {source: caPath, readOnly: true},
			}
		} else if name == gatus {
			wantMemory = 512 << 20
			wantPids = 64
			wantNanoCPUs = 2_000_000_000
			wantTmpfs = map[string]string{
				"/tmp":  "rw,noexec,nosuid,size=32m,uid=1000,gid=1000",
				"/data": "rw,noexec,nosuid,size=64m,uid=1000,gid=1000",
			}
			wantBinds = map[string]struct {
				source   string
				readOnly bool
			}{
				"/config/config.yaml": {source: gatusConfigPath, readOnly: true},
			}
		}
		if !item.HostConfig.ReadonlyRoot || item.HostConfig.Privileged || item.Config.Tty || item.Config.User != wantUser ||
			item.HostConfig.Memory != wantMemory || item.HostConfig.PidsLimit != wantPids || item.HostConfig.NanoCPUs != wantNanoCPUs {
			t.Fatal("fixture container lacks the required read-only, non-root, no-TTY sandbox settings")
		}
		if !containsString(item.HostConfig.CapDrop, "ALL") || !containsString(item.HostConfig.SecurityOpt, "no-new-privileges:true") {
			t.Fatal("fixture container retained capabilities or privilege escalation")
		}
		if len(item.HostConfig.Tmpfs) != len(wantTmpfs) {
			t.Fatal("fixture container has an unexpected temporary filesystem set")
		}
		for destination, options := range wantTmpfs {
			if item.HostConfig.Tmpfs[destination] != options {
				t.Fatal("fixture container temporary filesystem limits differ from the declared bound")
			}
		}
		if len(item.HostConfig.PortBindings) != 0 {
			t.Fatal("fixture container unexpectedly publishes a host port")
		}
		for _, env := range item.Config.Env {
			if strings.Contains(strings.ToLower(env), "proxy=") || strings.Contains(strings.ToLower(env), "token=") && name == cli {
				t.Fatal("actual CLI container inherited a proxy or credential environment variable")
			}
		}
		binds := make(map[string]bool, len(wantBinds))
		for _, mount := range item.Mounts {
			if strings.Contains(mount.Source, "docker.sock") || strings.Contains(mount.Destination, "docker.sock") {
				t.Fatal("fixture container unexpectedly exposes a container control socket")
			}
			switch mount.Type {
			case "bind":
				want, ok := wantBinds[mount.Destination]
				if !ok || mount.Source != want.source || mount.RW == want.readOnly {
					t.Fatal("fixture container has an unexpected or writable bind mount")
				}
				binds[mount.Destination] = true
			default:
				t.Fatal("fixture container has an unapproved mount type")
			}
		}
		if len(binds) != len(wantBinds) {
			t.Fatal("fixture container bind-mount set differs from the exact input contract")
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func ensureActualCLIProviderSubnetAvailable(t *testing.T, ctx context.Context) {
	t.Helper()
	_, wanted, err := net.ParseCIDR(actualCLIProviderSubnet)
	if err != nil {
		t.Fatal("the configured local source-QA subnet is invalid")
	}
	routes, err := exec.CommandContext(ctx, "ip", "-o", "route", "show").Output()
	if err != nil {
		t.Fatal("could not check host routing for a conflicting local source-QA subnet")
	}
	for _, line := range strings.Split(string(routes), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "default" {
			continue
		}
		_, route, parseErr := net.ParseCIDR(fields[0])
		if parseErr != nil {
			if address := net.ParseIP(fields[0]); address != nil && address.To4() != nil {
				route = &net.IPNet{IP: address.To4(), Mask: net.CIDRMask(32, 32)}
			} else {
				continue
			}
		}
		if subnetsOverlap(wanted, route) {
			t.Fatal("the isolated source-QA subnet conflicts with an existing host route")
		}
	}
	networkIDs, err := exec.CommandContext(ctx, "docker", "network", "ls", "--quiet").Output()
	if err != nil {
		t.Fatal("could not check Docker network allocations before creating the source-QA network")
	}
	for _, id := range strings.Fields(string(networkIDs)) {
		output, inspectErr := exec.CommandContext(ctx, "docker", "network", "inspect", "--format", "{{json .IPAM.Config}}", id).Output()
		if inspectErr != nil {
			t.Fatal("could not inspect Docker network allocations before creating the source-QA network")
		}
		var allocations []struct {
			Subnet string `json:"Subnet"`
		}
		if json.Unmarshal(output, &allocations) != nil {
			t.Fatal("Docker network allocation metadata was not valid JSON")
		}
		for _, allocation := range allocations {
			_, existing, parseErr := net.ParseCIDR(allocation.Subnet)
			if parseErr == nil && subnetsOverlap(wanted, existing) {
				t.Fatal("the isolated source-QA subnet overlaps an existing Docker network")
			}
		}
	}
}

func subnetsOverlap(left, right *net.IPNet) bool {
	return left != nil && right != nil && (left.Contains(right.IP) || right.Contains(left.IP))
}

func waitActualCLIGatusReady(ctx context.Context, endpoint string) bool {
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	deadline, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	for deadline.Err() == nil {
		request, err := http.NewRequestWithContext(deadline, http.MethodGet, endpoint+"/health", nil)
		if err == nil {
			response, requestErr := client.Do(request)
			if requestErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return true
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func dockerActualCLIChildInvoker(network, container, planRoot string) operationPlanProbeChildInvoker {
	return func(ctx context.Context, _ *os.File, args, env []string, stdout, stderr io.Writer) error {
		if ctx == nil || ctx.Err() != nil || container == "" || network == "" || planRoot == "" || len(args) == 0 || args[0] != "verify" {
			return fmt.Errorf("isolated CLI child is unavailable")
		}
		commandArgs := []string{"exec", "--interactive"}
		for _, value := range env {
			if strings.HasPrefix(value, "SSL_CERT_FILE=") {
				if value != "SSL_CERT_FILE=/fixture-ca.pem" {
					return fmt.Errorf("isolated CLI CA path is not the mounted fixture CA")
				}
				commandArgs = append(commandArgs, "--env", value)
			} else if value == "PATH=/usr/local/bin:/usr/bin:/bin" {
				commandArgs = append(commandArgs, "--env", value)
			} else {
				return fmt.Errorf("isolated CLI child environment contains an unapproved value")
			}
		}
		readEnd, writeEnd, err := os.Pipe()
		if err != nil {
			return err
		}
		defer readEnd.Close()
		defer writeEnd.Close()
		commandArgs = append(commandArgs, "--workdir", planRoot, container, "/launcher", "run", "/datapan-cli")
		commandArgs = append(commandArgs, args...)
		command := exec.CommandContext(ctx, "docker", commandArgs...)
		command.Stdin = readEnd
		command.Stdout, command.Stderr = stdout, stderr
		err = command.Run()
		if ctx.Err() != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// Docker exec cancellation closes the stdin stream. The in-container
			// launcher sends TERM and escalates to KILL; removing the entire child
			// sandbox here ensures no detached CLI process can survive the test.
			_ = exec.CommandContext(cleanupCtx, "docker", "kill", "--signal=KILL", container).Run()
			return ctx.Err()
		}
		return err
	}
}

func (monitor *actualCLIContainerMonitor) run() {
	defer close(monitor.done)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-monitor.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			output, err := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", monitor.container).Output()
			cancel()
			if err == nil {
				used, _, ok := parseDockerMemoryUsage(strings.TrimSpace(string(output)))
				if ok {
					monitor.mu.Lock()
					if used > monitor.peakBytes {
						monitor.peakBytes = used
					}
					monitor.samples++
					monitor.mu.Unlock()
				}
			}
		}
	}
}

func (monitor *actualCLIContainerMonitor) Stop() {
	select {
	case <-monitor.stop:
		return
	default:
		close(monitor.stop)
		<-monitor.done
	}
}

func (monitor *actualCLIContainerMonitor) Snapshot() (peakBytes uint64, samples int) {
	if monitor == nil {
		return 0, 0
	}
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	return monitor.peakBytes, monitor.samples
}

func parseDockerMemoryUsage(value string) (used, limit uint64, ok bool) {
	left, right, found := strings.Cut(value, " /")
	if !found {
		return 0, 0, false
	}
	parse := func(input string) uint64 {
		input = strings.TrimSpace(input)
		unitStart := len(input)
		for unitStart > 0 && (input[unitStart-1] < '0' || input[unitStart-1] > '9') && input[unitStart-1] != '.' {
			unitStart--
		}
		number, err := strconv.ParseFloat(strings.TrimSpace(input[:unitStart]), 64)
		if err != nil {
			return 0
		}
		unit := strings.TrimSpace(input[unitStart:])
		multipliers := map[string]float64{"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "kB": 1e3, "MB": 1e6, "GB": 1e9}
		multiplier, ok := multipliers[unit]
		if !ok {
			return 0
		}
		return uint64(number * multiplier)
	}
	used, limit = parse(left), parse(right)
	return used, limit, used > 0 && limit > 0
}
