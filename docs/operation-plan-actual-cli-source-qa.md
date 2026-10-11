# Actual CLI operation-plan source QA

The opt-in actual-CLI target builds the CLI from merged source revision `d4226321c1a4c6c7aa091753dc6f03f4ab04cddd` (reviewed source `1153f733b1cf45e73c953bb9091322b23f08eeb0`, identical Git tree `bf48150ddd3fa8d13537aa0e99edf3d724210e98`) and verifies that the checkout is clean before compiling. These revisions include exact source-qualified operation selection. Health passes the sealed expectation's source ID alongside the operation ID; the CLI filters exact, case-sensitive source IDs before selecting a shard range and binds the chosen source into the receipt. Omitting the source selector retains the CLI's existing conservative global selection behavior.

The test uses local source-QA version `v0.1.41`, hashes the fresh binary, and binds that exact digest into the Health runtime lock. This test-only version is not a published release. A supplied binary is accepted only when its bytes match that fresh build. The historical `acf060e71e2329b6a04ad4ab0abf669fbbfe9dac` source predates source-qualified selection; artifacts or results from it are historical evidence only and are not accepted as the current actual-CLI source-QA candidate. The current isolated reproduction, smoke, recovery and full-population target must all use the fresh binary built from the merged source above.

Set `HEALTH_OPERATION_ACTUAL_CLI_SOURCE` to an absolute path to that clean checkout. Run the controlled no-dispatch window-drain recovery and eight-case protocol/classification smoke before the full manifest-derived population:

```sh
HEALTH_OPERATION_ACTUAL_CLI_SOURCE=/absolute/path/to/datapan-cli \
  make operation-plan-actual-cli-recovery

HEALTH_OPERATION_ACTUAL_CLI_SOURCE=/absolute/path/to/datapan-cli \
  make operation-plan-actual-cli-smoke

HEALTH_OPERATION_ACTUAL_CLI_SOURCE=/absolute/path/to/datapan-cli \
  make operation-plan-actual-cli-full
```

The full target runs all 12,666 pinned identities through the production Health scheduler, worker, durable stores, actual compiled CLI child, and pinned Gatus. The controller has a 90-minute source-QA bound; the Go test has a 120-minute outer bound for fixture setup and teardown. These are test-harness limits, not production cadence or provider-quota changes. Docker keeps the synthetic provider, Gatus, and CLI inside a checked internal-only network with no host port mappings; the host reaches Gatus and aggregate provider metrics at their fixed container addresses on that network, while every actual CLI child runs inside the same network. The CLI container receives only the hashed binary, read-only installed projection and local CA, plus its private receipt directory. The fixture has no provider credentials and reports only aggregate request, receipt, delivery, memory, and identity counts. Its response outcomes are synthetic and do not establish live provider health.

The mounted projection is self-contained at one root: it contains `reports/operation-observation-plan/index.json`, `.datapan/registry-install.json`, and `.datapan/release/manifest.json`. The Health runner derives the CLI child working directory from that canonical index path, so the parent test process working directory is irrelevant. This validates the Health projection layout used by this target; it does not claim compatibility with every ordinary CLI installation layout.

The recovery target seeds each exact synthetic quota scope with one valid active lease from the prior accounting window, then sends one selected operation through the production worker. The worker must persist a typed no-request window-drain attempt without invoking the CLI or contacting the local provider. The test releases only those local seeded leases through the quota authority, waits for the persisted 30-second cooldown, and proves the same operation succeeds through the compiled CLI and exact-key Gatus readback. This controlled state is isolated to the source-QA fixture; it does not alter provider quotas or the full-population run.

The runtime-bundle installer test covers bounded acceptance of the plan-bearing release manifest and its immutable binding. The actual-CLI target stages the complete read-only artifact projection separately; the installer test does not download the entire operation-artifact closure.
