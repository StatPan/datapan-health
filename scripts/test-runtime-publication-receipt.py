#!/usr/bin/env python3
"""Execute the actual workflow receipt step without publication or credentials."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


class PublicationReceiptTest(unittest.TestCase):
    def test_verified_upload_and_reconciliation_both_have_fresh_available_receipts(self):
        workflow = (Path(__file__).resolve().parent.parent / '.github/workflows/publish-runtime-image.yml').read_text()
        step = workflow.split('      - name: Write secret-free release receipt\n', 1)[1].split('      - name: Upload release evidence\n', 1)[0]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1]).strip()
        source, digest = 'a' * 40, 'sha256:' + 'b' * 64
        image = 'ghcr.io/statpan/datapan-health-runtime@' + digest
        rollback = 'ghcr.io/statpan/datapan-health-runtime@sha256:' + 'c' * 64
        for upload in ('true', 'false'):
            with self.subTest(new_upload=upload), tempfile.TemporaryDirectory(prefix='health-receipt-contract-') as directory:
                root = Path(directory)
                output = root / 'dist/images'
                output.mkdir(parents=True)
                for name in ('runtime.oci.tar', 'governance-bundle.tar'):
                    (output / name).write_bytes(b'synthetic test artifact, no provider data')
                config = root / 'config'
                config.mkdir()
                lock = {'cli': {'source_sha': 'd' * 40, 'release': 'v0.1.40',
                    'linux_binaries': {'arm64': {'binary_sha256': 'e' * 64}}},
                    'registry': {'dataset_revision': 'f' * 40,
                        'manifest_sha256': '1' * 64, 'catalog_sha256': '2' * 64}}
                (config / 'runtime-dependencies.json').write_text(json.dumps(lock))
                (config / 'gatus.yaml').write_text('synthetic configuration; no operational credentials\n')
                environment = dict(os.environ, SOURCE_SHA=source, ROLLBACK_IMAGE=rollback,
                    RELEASE_ARTIFACT='datapan-health-runtime-release-' + source,
                    RECEIPT_MAX_AGE_SECONDS='900', local_runtime_digest=digest,
                    GITHUB_REPOSITORY='StatPan/datapan-health', GITHUB_RUN_ID='123',
                    GITHUB_WORKFLOW_REF='StatPan/datapan-health/.github/workflows/publish-runtime-image.yml@refs/heads/main')
                run_script = script.replace('${{ steps.existing.outputs.publish }}', upload)
                run_script = run_script.replace('${{ steps.promoted.outputs.image }}', image)
                run_script = run_script.replace('${{ steps.promoted.outputs.digest }}', digest)
                result = subprocess.run(['bash', '-euo', 'pipefail', '-c', run_script], cwd=root,
                    env=environment, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, 'workflow receipt construction failed')
                receipt = json.loads((output / 'runtime-release-receipt.json').read_text())
                self.assertEqual(receipt['schema_version'], 'statpan.datapan-health-runtime-release.v2')
                self.assertEqual(receipt['runtime_dependencies'], {
                    'dependency_lock_sha256': hashlib.sha256((config / 'runtime-dependencies.json').read_bytes()).hexdigest(),
                    'cli_source_sha': lock['cli']['source_sha'], 'cli_release': lock['cli']['release'],
                    'cli_binary_sha256': lock['cli']['linux_binaries']['arm64']['binary_sha256'],
                    'registry_dataset_revision': lock['registry']['dataset_revision'],
                    'registry_manifest_sha256': lock['registry']['manifest_sha256'],
                    'registry_catalog_sha256': lock['registry']['catalog_sha256']})
                self.assertEqual(receipt['gatus_config_sha256'], hashlib.sha256((config / 'gatus.yaml').read_bytes()).hexdigest())
                self.assertIs(receipt['published'], True, 'verified available image became inadmissible on reconciliation')
                self.assertEqual(receipt['github']['source_revision'], source)
                self.assertEqual(receipt['package']['oci_revision_label'], source)
                self.assertEqual(receipt['package']['image'], image)
                self.assertEqual(receipt['local_release']['oci_manifest_digest'], digest)
                self.assertEqual(receipt['declared_rollback_image'], rollback)
                self.assertEqual(receipt['max_age_seconds'], 900)
                issued = datetime.datetime.fromisoformat(receipt['issued_at'].replace('Z', '+00:00'))
                expires = datetime.datetime.fromisoformat(receipt['expires_at'].replace('Z', '+00:00'))
                self.assertEqual((expires - issued).total_seconds(), 900)
                for field, name in (('runtime_oci_sha256', 'runtime.oci.tar'), ('governance_bundle_sha256', 'governance-bundle.tar')):
                    self.assertEqual(receipt['local_release'][field], hashlib.sha256((output / name).read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
