#!/usr/bin/env python3
"""Local container proof only: synthetic CLI -> real adapter/Gatus -> public GET.
Run with a built RUNTIME_IMAGE and local Compose Gatus/public-status running.
Print aggregate receipts only; never print provider requests, targets or rows.
"""
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

root = Path(__file__).resolve().parent.parent
image = os.environ.get('RUNTIME_IMAGE', 'datapan-health-runtime:test')
config = json.loads((root / 'config/canaries.json').read_text())
project = json.loads(subprocess.check_output(['docker', 'compose', 'config', '--format', 'json'], cwd=root))['name']

def command(*args):
    return subprocess.check_output(list(args), cwd=root, stderr=subprocess.DEVNULL).decode().strip()

def get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)

def lines(path):
    return len(path.read_text().splitlines()) if path.exists() else 0

proof = []
with tempfile.TemporaryDirectory(prefix='health-pipeline-proof-') as directory:
    work = Path(directory)
    command('env', 'CGO_ENABLED=0', 'go', 'build', '-o', str(work / 'fake-cli'), './scripts/testdata/fake-cli/main.go')
    archive, journal = work / 'receipts.jsonl', work / 'deliveries.jsonl'
    for phase, mode, token, ready_expected in (
        ('normal', 'healthy', 'local-synthetic-token', True),
        ('partial_admission_failure', 'one_valid', 'local-synthetic-token', False),
        ('admission_failure', 'bad_registry', 'local-synthetic-token', False),
        ('delivery_failure_after_archive', 'healthy', 'invalid-synthetic-token', False),
        ('provider_timeout_1', 'provider_timeout', 'local-synthetic-token', True),
        ('provider_timeout_2', 'provider_timeout', 'local-synthetic-token', True),
        ('cli_receipt_missing', 'no_receipt', 'local-synthetic-token', False),
        ('recovery_1', 'healthy', 'local-synthetic-token', True),
        ('recovery_2', 'healthy', 'local-synthetic-token', True),
    ):
        (work / 'mode').write_text(mode)
        at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        state = {'version': 1, 'slots': {c['operation_id']: {'last_claimed_slot': 0, 'next_due': at} for c in config['canaries']}}
        (work / 'state.json').write_text(json.dumps(state))
        before_archive, before_journal = lines(archive), lines(journal)
        _, before_public = get('http://127.0.0.1:8082/datapan/v1/dependencies')
        before_times = {o['operation_id']: o.get('observed_at') for o in before_public['operations']}
        phase_start = datetime.datetime.fromisoformat(at).replace(microsecond=0)
        cid = command('docker', 'run', '-d', '--read-only', '--user', str(os.getuid()) + ':' + str(os.getgid()), '--network', project + '_default', '-p', '127.0.0.1::8081', '--entrypoint', '/health-scheduler',
            '-v', str(root / 'config') + ':/config:ro', '-v', directory + ':/proof',
            '-e', 'CANARY_CONFIG=/config/canaries.json', '-e', 'DATAPAN_BIN=/proof/fake-cli', '-e', 'HEALTH_RUNNER_BIN=/health-runner',
            '-e', 'CLI_RUNTIME_ENV=CANARY_CONFIG,SMOKE_CONTROL_FILE', '-e', 'SMOKE_CONTROL_FILE=/proof/mode',
            '-e', 'SCHEDULER_STATE=/proof/state.json', '-e', 'RECEIPT_ARCHIVE=/proof/receipts.jsonl', '-e', 'RECEIPT_DELIVERY_JOURNAL=/proof/deliveries.jsonl',
            '-e', 'GATUS_URL=http://gatus:8080', '-e', 'GATUS_TOKEN=' + token, image)
        try:
            port = command('docker', 'port', cid, '8081/tcp').split(':')[-1]
            url = 'http://127.0.0.1:' + port
            report = None
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                try:
                    code, report = get(url + '/status')
                    terminal = all(c.get('last_accepted') or c.get('reason') == 'registry_identity' for c in report['canaries'])
                    settled = all(c.get('last_delivered') or c.get('reason') in ('registry_identity', 'delivery_failed') for c in report['canaries'])
                    if terminal and settled:
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.2)
            if report is None or not terminal or not settled:
                raise RuntimeError('bounded pipeline did not settle: ' + phase)
            if (code == 200) != ready_expected or report['ready'] != ready_expected:
                raise RuntimeError('incorrect readiness: ' + phase)
            stored = lines(archive) - before_archive
            accepted = lines(journal) - before_journal
            if phase == 'partial_admission_failure' and (stored != 1 or accepted != 1):
                raise RuntimeError('one working canary concealed nine rejections')
            if phase == 'admission_failure' and (stored or accepted):
                raise RuntimeError('invalid evidence entered a sink')
            if phase == 'delivery_failure_after_archive' and (stored != 10 or accepted):
                raise RuntimeError('archive concealed failed delivery')
            if ready_expected and (stored != 10 or accepted != 10):
                raise RuntimeError('healthy pipeline incomplete')
            public_deadline = time.monotonic() + 20
            while True:
                public_code, public = get('http://127.0.0.1:8082/datapan/v1/dependencies')
                read_times = {o['operation_id']: o.get('observed_at') for o in public.get('operations', [])}
                delivered_ids = {c['operation_id'] for c in report['canaries'] if c.get('last_delivered')}
                current = len(read_times) == 10 and all(read_times.get(key) and datetime.datetime.fromisoformat(read_times[key].replace('Z', '+00:00')) >= phase_start for key in delivered_ids)
                if not accepted or current:
                    break
                if time.monotonic() > public_deadline:
                    raise RuntimeError('acknowledged observations absent from public readback: ' + phase)
                time.sleep(0.2)
            if any(value != before_times.get(key) for key, value in read_times.items() if key not in delivered_ids):
                raise RuntimeError('rejected/undelivered observation changed public status')
            if public_code != 200 or len(public['operations']) != 10:
                raise RuntimeError('public readback unavailable')
            observed_states = {}
            for operation in public['operations']:
                key = operation['raw_observation_state']
                observed_states[key] = observed_states.get(key, 0) + 1
            if phase == 'provider_timeout_2' and observed_states != {'failed': 10}:
                raise RuntimeError('provider failure not visible through Gatus')
            if phase == 'recovery_2' and observed_states != {'succeeded': 10}:
                raise RuntimeError('public recovery did not complete')
            proof.append(dict(phase=phase, self_http=code, archive_delta=stored, gatus_ack_delta=accepted, public_http=public_code, public_canaries=10, public_observation_time_binding='current_phase' if accepted else 'unchanged', public_observation_states=observed_states))
        finally:
            command('docker', 'rm', '-f', cid)
output = root / 'out/pipeline-proof.json'
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(dict(schema_version='datapan.health-local-pipeline-proof.v1', scope='synthetic_local_containers', source_head=command('git', 'rev-parse', 'HEAD'), runtime_image_id=command('docker', 'image', 'inspect', '--format', '{{.Id}}', image), image=image, phases=proof), indent=2) + '\n')
print(json.dumps(dict(output=str(output), phases=len(proof), result='passed')))
