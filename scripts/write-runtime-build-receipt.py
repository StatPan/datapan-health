#!/usr/bin/env python3
"""Validate local OCI bytes and write build evidence, never publication evidence."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile


def sha256_file(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_runtime_archive(path, revision, expected_digest):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('invalid source revision')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest):
        raise ValueError('invalid manifest digest')
    members, hashes, documents = {}, {}, {}
    total = 0
    with tarfile.open(path, mode='r:') as archive:
        for member in archive:
            name = member.name
            if name.startswith('/') or '..' in name.split('/') or name in members:
                raise ValueError('unsafe or duplicate OCI member')
            if member.isdir():
                continue
            if not member.isfile() or len(members) >= 4096:
                raise ValueError('invalid OCI member type or count')
            if name not in ('index.json', 'oci-layout') and not re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', name):
                raise ValueError('unexpected OCI member')
            total += member.size
            if total > 8 * 1024**3:
                raise ValueError('OCI byte limit exceeded')
            stream = archive.extractfile(member)
            digest, count = hashlib.sha256(), 0
            small = bytearray() if member.size <= 1024**2 else None
            while chunk := stream.read(1024**2):
                count += len(chunk)
                digest.update(chunk)
                if small is not None:
                    small.extend(chunk)
            if count != member.size:
                raise ValueError('truncated OCI member')
            hashes[name] = digest.hexdigest()
            members[name] = member.size
            if small is not None:
                documents[name] = bytes(small)
            if name.startswith('blobs/') and digest.hexdigest() != name.rsplit('/', 1)[1]:
                raise ValueError('OCI blob digest mismatch')

    def document(name):
        if name not in documents:
            raise ValueError('missing or oversized OCI metadata')
        result = json.loads(documents[name])
        if not isinstance(result, dict):
            raise ValueError('invalid OCI metadata')
        return result

    def descriptor(value):
        digest = value.get('digest', '')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('invalid OCI descriptor')
        name = 'blobs/sha256/' + digest[7:]
        if members.get(name) != value.get('size') or name not in hashes:
            raise ValueError('OCI descriptor size or member mismatch')
        return name

    if document('oci-layout').get('imageLayoutVersion') != '1.0.0':
        raise ValueError('unsupported OCI layout')
    index = document('index.json')
    manifests = index.get('manifests')
    if index.get('schemaVersion') != 2 or not isinstance(manifests, list) or not manifests:
        raise ValueError('invalid OCI index')
    if manifests[0].get('digest') != expected_digest:
        raise ValueError('local runtime manifest mismatch')
    image_configs = []

    def visit(value, depth=0):
        if depth > 4:
            raise ValueError('OCI index nesting limit')
        item = document(descriptor(value))
        if item.get('schemaVersion') != 2:
            raise ValueError('invalid OCI manifest version')
        if 'manifests' in item:
            children = item['manifests']
            if not isinstance(children, list) or not 1 <= len(children) <= 32:
                raise ValueError('invalid nested OCI index')
            for child in children:
                visit(child, depth + 1)
            return
        config = document(descriptor(item['config']))
        for layer in item['layers']:
            descriptor(layer)
        # BuildKit provenance may add unknown/unknown attestation manifests.
        if config.get('os') == 'linux' and config.get('architecture') == 'arm64':
            image_configs.append(config)
        elif config.get('os') != 'unknown' or config.get('architecture') != 'unknown':
            raise ValueError('unexpected OCI image platform')

    visit(manifests[0])
    if len(image_configs) != 1:
        raise ValueError('expected one ARM64 runtime image')
    labels = image_configs[0].get('config', {}).get('Labels', {})
    if labels.get('org.opencontainers.image.revision') != revision:
        raise ValueError('OCI source revision mismatch')
    return sha256_file(path)


def write_receipt(root, environment):
    output = root / 'dist/images'
    source = environment['SOURCE_SHA']
    digest = environment['local_runtime_digest']
    archive_sha = verify_runtime_archive(output / 'runtime.oci.tar', source, digest)
    checksums = (output / 'sha256sums.txt').read_text().splitlines()
    matches = [line.split(maxsplit=1)[0] for line in checksums
               if len(line.split(maxsplit=1)) == 2 and line.split(maxsplit=1)[1].lstrip('*').endswith('/runtime.oci.tar')]
    if matches != [archive_sha]:
        raise ValueError('runtime archive checksum mismatch')
    inputs = dict(line.split('=', 1) for line in (output / 'infra-image-inputs.env').read_text().splitlines()
                  if line and not line.startswith('#'))
    if inputs.get('DATAPAN_HEALTH_RELEASE_REVISION') != source or inputs.get('DATAPAN_HEALTH_RELEASE_PLATFORM') != 'linux/arm64':
        raise ValueError('build input identity mismatch')
    if inputs.get('DATAPAN_HEALTH_IMAGE') != 'ghcr.io/statpan/datapan-health-runtime@' + digest:
        raise ValueError('build image input mismatch')
    if environment['GITHUB_REPOSITORY'] != 'StatPan/datapan-health':
        raise ValueError('unexpected build repository')
    receipt = {
        'schema_version': 'statpan.datapan-health-runtime-build.v1',
        'issued_at': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
        'published': False,
        'deployment_admissible': False,
        'github': {'repository': environment['GITHUB_REPOSITORY'],
                   'workflow_path': '.github/workflows/publish-runtime-image.yml',
                   'workflow_ref': environment['GITHUB_WORKFLOW_REF'],
                   'run_id': environment['GITHUB_RUN_ID'], 'source_revision': source,
                   'artifact_name': environment['BUILD_ARTIFACT']},
        'local_build': {'platform': 'linux/arm64', 'oci_revision_label': source,
                        'oci_manifest_digest': digest, 'runtime_oci_sha256': archive_sha,
                        'infra_inputs_sha256': sha256_file(output / 'infra-image-inputs.env'),
                        'checksums_sha256': sha256_file(output / 'sha256sums.txt'),
                        'governance_bundle_sha256': sha256_file(output / 'governance-bundle.tar'),
                        'dependency_lock_sha256': sha256_file(root / 'config/runtime-dependencies.json'),
                        'gatus_config_sha256': sha256_file(root / 'config/gatus.yaml')},
    }
    path = output / 'runtime-build-receipt.json'
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    temporary.replace(path)
    return receipt


if __name__ == '__main__':
    try:
        write_receipt(Path.cwd(), os.environ)
    except (KeyError, ValueError, OSError, tarfile.TarError, TypeError):
        raise SystemExit('runtime build evidence validation failed') from None
