#!/usr/bin/env python3
"""Create current, synthetic local test receipts. Never use production receipts."""
import datetime
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
config = json.loads((root / 'config/canaries.json').read_text())
catalog = json.loads((root / 'config/registry/health-probe-catalog.json').read_text())
output = root / 'out/smoke-fixtures'
output.mkdir(parents=True, exist_ok=True)
for name in ('healthy.json', 'unhealthy.json'):
    receipt = json.loads((root / 'testdata/receipts/v1' / name).read_text())
    entry = next(item for item in catalog['entries'] if item['aliases']['cli_operation_key'] == receipt['operation']['operation_key'])
    provenance = config['consumption_provenance']
    receipt['registry'] = dict(dataset_id='StatPan/datapan-registry', dataset_revision=provenance['registry_dataset_revision'], registry_sha256=provenance['source_registry_sha256'], manifest_sha256=provenance['release_manifest_sha256'])
    receipt['policy'] = entry['policy']
    receipt['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output / name).write_text(json.dumps(receipt))
