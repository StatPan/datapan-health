#!/usr/bin/env python3
"""Exercise build preservation with local synthetic OCI bytes only."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('build_receipt', ROOT / 'scripts/write-runtime-build-receipt.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = 'a' * 40


def archive(path, *, revision=SOURCE, architecture='arm64', corrupt=False,
            missing=False, duplicate=False, unsafe=False, descriptor_size=False):
    blobs = {}

    def blob(data):
        digest = hashlib.sha256(data).hexdigest()
        blobs['blobs/sha256/' + digest] = data
        return {'digest': 'sha256:' + digest, 'size': len(data)}

    config = blob(json.dumps({'os': 'linux', 'architecture': architecture,
                             'config': {'Labels': {'org.opencontainers.image.revision': revision}}}).encode())
    layer = blob(b'synthetic layer; no provider data')
    manifest = blob(json.dumps({'schemaVersion': 2, 'config': config, 'layers': [layer]}).encode())
    if descriptor_size:
        manifest['size'] += 1
    files = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}',
             'index.json': json.dumps({'schemaVersion': 2, 'manifests': [manifest]}).encode(), **blobs}
    if corrupt:
        files['blobs/sha256/' + config['digest'][7:]] = b'{}'
    if missing:
        del files['blobs/sha256/' + layer['digest'][7:]]
    if unsafe:
        files['../fixture'] = b'unsafe'
    with tarfile.open(path, 'w') as output:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            output.addfile(member, io.BytesIO(data))
        if duplicate:
            member = tarfile.TarInfo('index.json')
            member.size = len(files['index.json'])
            output.addfile(member, io.BytesIO(files['index.json']))
    return manifest['digest']


class RuntimeBuildReceiptTest(unittest.TestCase):
    def test_archive_identity_and_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runtime.oci.tar'
            digest = archive(path)
            self.assertEqual(module.verify_runtime_archive(path, SOURCE, digest), module.sha256_file(path))
            cases = ({'revision': 'b' * 40}, {'architecture': 'amd64'}, {'corrupt': True},
                     {'missing': True}, {'duplicate': True}, {'unsafe': True}, {'descriptor_size': True})
            for case in cases:
                with self.subTest(case=case):
                    digest = archive(path, **case)
                    with self.assertRaises((ValueError, KeyError)):
                        module.verify_runtime_archive(path, SOURCE, digest)
            digest = archive(path)
            with self.assertRaises(ValueError):
                module.verify_runtime_archive(path, SOURCE, 'sha256:' + '0' * 64)
            path.write_bytes(b'not an OCI tar archive')
            with self.assertRaises(tarfile.TarError):
                module.verify_runtime_archive(path, SOURCE, digest)

    def test_build_receipt_is_not_a_publication_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'dist/images'
            output.mkdir(parents=True)
            config = root / 'config'
            config.mkdir()
            for name in ('runtime-dependencies.json', 'gatus.yaml'):
                (config / name).write_text('synthetic configuration\n')
            (output / 'governance-bundle.tar').write_bytes(b'synthetic governance bundle')
            digest = archive(output / 'runtime.oci.tar')
            archive_sha = module.sha256_file(output / 'runtime.oci.tar')
            (output / 'sha256sums.txt').write_text(archive_sha + '  dist/images/runtime.oci.tar\n')
            (output / 'infra-image-inputs.env').write_text(
                'DATAPAN_HEALTH_RELEASE_REVISION=' + SOURCE + '\n'
                'DATAPAN_HEALTH_RELEASE_PLATFORM=linux/arm64\n'
                'DATAPAN_HEALTH_IMAGE=ghcr.io/statpan/datapan-health-runtime@' + digest + '\n')
            environment = dict(SOURCE_SHA=SOURCE, local_runtime_digest=digest,
                               GITHUB_REPOSITORY='StatPan/datapan-health', GITHUB_RUN_ID='123',
                               GITHUB_WORKFLOW_REF='StatPan/datapan-health/.github/workflows/publish-runtime-image.yml@refs/heads/main',
                               BUILD_ARTIFACT='datapan-health-runtime-build-' + SOURCE)
            receipt = module.write_receipt(root, environment)
            self.assertEqual(receipt['schema_version'], 'statpan.datapan-health-runtime-build.v1')
            self.assertIs(receipt['published'], False)
            self.assertIs(receipt['deployment_admissible'], False)
            self.assertNotIn('package', receipt)
            self.assertNotIn('conclusion', receipt['github'])
            self.assertEqual(receipt['local_build']['runtime_oci_sha256'], archive_sha)
            self.assertEqual(json.loads((output / 'runtime-build-receipt.json').read_text()), receipt)
            (output / 'runtime-build-receipt.json').unlink()
            (output / 'sha256sums.txt').write_text('0' * 64 + '  dist/images/runtime.oci.tar\n')
            with self.assertRaises(ValueError):
                module.write_receipt(root, environment)
            self.assertFalse((output / 'runtime-build-receipt.json').exists())

    def test_workflow_upload_precedes_registry_failure_points(self):
        workflow = (ROOT / '.github/workflows/publish-runtime-image.yml').read_text()
        positions = [workflow.index('- name: ' + name) for name in (
            'Run the existing release contract and local checks',
            'Verify local OCI identity and write build-only evidence',
            'Preserve verified build before registry access',
            'Log in to GHCR with workflow-scoped authority',
            'Publish the exact runtime target once',
            'Verify promoted digest and runtime identity', 'Write secret-free release receipt',
            'Upload release evidence')]
        self.assertEqual(positions, sorted(positions))
        step = workflow[positions[2]:positions[3]]
        self.assertNotIn('if:', step)
        self.assertIn('name: ${{ env.BUILD_ARTIFACT }}', step)
        self.assertIn('dist/images/runtime-build-receipt.json', step)
        self.assertNotIn('runtime-release-receipt.json', step)
        self.assertIn('if-no-files-found: error', step)
        self.assertIn('retention-days: 30', step)


if __name__ == '__main__':
    unittest.main()
