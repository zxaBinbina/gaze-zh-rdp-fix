#!/usr/bin/env python3
"""Build and test the pinned KRDP repair without installing system files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'third_party/krdp'


def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deps-root', type=Path, help='Root containing usr/ from unpacked Fedora development RPMs')
    parser.add_argument('--jobs', type=int, default=min(os.cpu_count() or 2, 4))
    args = parser.parse_args()
    meta = json.loads((SOURCE / 'UPSTREAM.json').read_text())
    archive = SOURCE / meta['archive']
    if hashlib.sha256(archive.read_bytes()).hexdigest() != meta['sha256']:
        raise SystemExit('KRDP source archive checksum mismatch')
    inputs = [archive, SOURCE / 'CMakeLists.txt', *(SOURCE / p for p in meta['patches']), *sorted((SOURCE / 'tests').glob('*.cpp'))]
    digest = hashlib.sha256(b''.join(p.read_bytes() for p in inputs)).hexdigest()[:16]
    work = ROOT / 'target/krdp-fix' / digest
    source = work / 'krdp-6.7.5'
    work.mkdir(parents=True, exist_ok=True)
    if not (work / '.prepared').exists():
        if source.exists():
            raise SystemExit(f'Incomplete prior extraction: move {work} aside and retry')
        with tarfile.open(archive) as tar:
            tar.extractall(work, filter='data')
        for patch in meta['patches']:
            run('patch', '-p1', '--fuzz=0', '--batch', '-i', SOURCE / patch, cwd=source)
        shutil.copy2(SOURCE / 'CMakeLists.txt', source / 'CMakeLists.txt')
        shutil.copytree(SOURCE / 'tests', source / 'local-tests')
        (work / '.prepared').touch()
    deps = args.deps_root
    if deps is None and (ROOT / 'target/krdp-deps/usr/include/KPipeWire').exists():
        deps = ROOT / 'target/krdp-deps'
    build = work / 'build'
    run('cmake', '-S', source, '-B', build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=RelWithDebInfo',
        '-DKRDP_DEPS_ROOT=' + (str(deps.resolve()) if deps else ''))
    run('cmake', '--build', build, '-j', args.jobs)
    run('ctest', '--test-dir', build, '--output-on-failure')
    artifact = ROOT / 'target/krdp-fix/libKRdp.so.6.7.5'
    shutil.copy2(build / artifact.name, artifact)
    (artifact.parent / 'build-info.json').write_text(json.dumps({
        'upstream': meta, 'input_fingerprint': digest, 'library_sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
        'build_directory': str(build.relative_to(ROOT)), 'tests': 'frame-acknowledgement and progressive-geometry passed',
    }, indent=2) + '\n')
    print(f'Built and tested: {artifact}')


if __name__ == '__main__':
    main()
