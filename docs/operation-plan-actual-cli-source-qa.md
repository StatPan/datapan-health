# Actual CLI operation-plan source QA

The opt-in actual-CLI target builds the CLI from the merged source revision `acf060e71e2329b6a04ad4ab0abf669fbbfe9dac` and verifies that the checkout is clean before compiling. The test uses the local source-QA version `v0.1.41`, then hashes the fresh binary and binds that exact digest into the Health runtime lock. This test-only version is not a published release. A supplied binary is accepted only when its bytes match that fresh build.

Set `HEALTH_OPERATION_ACTUAL_CLI_SOURCE` to an absolute path to that clean checkout. Run the eight-case protocol and classification smoke first, then the full manifest-derived population:

```sh
HEALTH_OPERATION_ACTUAL_CLI_SOURCE=/absolute/path/to/datapan-cli \
  make operation-plan-actual-cli-smoke

HEALTH_OPERATION_ACTUAL_CLI_SOURCE=/absolute/path/to/datapan-cli \
  make operation-plan-actual-cli-full
```

The full target runs all 12,666 pinned identities through the production Health scheduler, worker, durable stores, actual compiled CLI child, and pinned Gatus. The controller has a 90-minute source-QA bound; the Go test has a 120-minute outer bound for fixture setup and teardown. These are test-harness limits, not production cadence or provider-quota changes. Docker keeps the synthetic provider, Gatus, and CLI inside a checked internal-only network with no host port mappings; the host reaches Gatus and aggregate provider metrics at their fixed container addresses on that network, while every actual CLI child runs inside the same network. The CLI container receives only the hashed binary, read-only installed projection and local CA, plus its private receipt directory. The fixture has no provider credentials and reports only aggregate request, receipt, delivery, memory, and identity counts. Its response outcomes are synthetic and do not establish live provider health.

The mounted projection is self-contained at one root: it contains `reports/operation-observation-plan/index.json`, `.datapan/registry-install.json`, and `.datapan/release/manifest.json`. The Health runner derives the CLI child working directory from that canonical index path, so the parent test process working directory is irrelevant. This validates the Health projection layout used by this target; it does not claim compatibility with every ordinary CLI installation layout.

The runtime-bundle installer test covers bounded acceptance of the plan-bearing release manifest and its immutable binding. The actual-CLI target stages the complete read-only artifact projection separately; the installer test does not download the entire operation-artifact closure.
