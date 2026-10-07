#!/usr/bin/env python3
"""Package the rebuilt GUI and desktop integrations using upstream RPM manifests.

Run build-combined-rpm.py first. Requires PyYAML and rpm-build.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

import yaml

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
OUTPUT = ROOT / 'dist/packages/x86_64'


def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def package(manifest):
    values = {
        'VERSION': VERSION, 'ARCH': 'x86_64', 'PACKAGE_RELEASE': '1',
        'RPM_GSTREAMER_BASE': 'gstreamer1-plugins-base',
        'RPM_GSTREAMER_GOOD': 'gstreamer1-plugins-good',
        'RPM_GSTREAMER_PIPEWIRE': 'pipewire-gstreamer',
    }
    text = manifest.read_text()
    # The upstream recipe injects native SONAME dependencies here. rpmbuild
    # derives those directly from our rebuilt ELF files instead.
    text = re.sub(r'^\$\{(?:RPM|DEB)_LIB_DEPENDS\}\s*$', '', text, flags=re.M)
    text = re.sub(r'\$\{([^}]+)\}', lambda m: values.get(m[1], ''), text)
    config = yaml.safe_load(text)
    name = config['name']
    work = Path(tempfile.mkdtemp(prefix=name + '-', dir=ROOT / 'target/ui-rpms'))
    payload = work / 'payload'
    payload.mkdir()
    files = []
    for entry in config['contents']:
        if entry.get('packager', 'rpm') != 'rpm':
            continue
        source = ROOT / entry['src']
        destination = Path(entry['dst'])
        assert destination.is_absolute() and '..' not in destination.parts
        mode = entry.get('file_info', {}).get('mode', 0o644)
        sources = sorted(p for p in source.rglob('*') if p.is_file()) if source.is_dir() else [source]
        for path in sources:
            target = destination / path.relative_to(source) if source.is_dir() else destination
            dest = payload / str(target).lstrip('/')
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dest)
            dest.chmod(mode)
            flag = '%config(noreplace) ' if entry.get('type') == 'config|noreplace' else ''
            files.append(f'{flag}%attr({mode:04o},root,root) {target}')
    rpm = config.get('overrides', {}).get('rpm', {})
    requirements = rpm.get('depends', config.get('depends', []))
    recommends = rpm.get('recommends', [])
    scripts = {**config.get('scripts', {}), **rpm.get('scripts', {})}
    spec = f'''%global debug_package %{{nil}}
%global __os_install_post %{{nil}}
Name: {name}
Version: {VERSION}
Release: 1%{{?dist}}
Summary: {config['description']}
License: {config['license']}
URL: {config['homepage']}
BuildArch: x86_64
'''
    spec += ''.join(f'Requires: {r}\n' for r in requirements)
    spec += ''.join(f'Recommends: {r}\n' for r in recommends)
    spec += f'''
%description
{config['description']}

%prep
%build
%install
mkdir -p %{{buildroot}}
cp -a "%{{_topdir}}/payload/." %{{buildroot}}/
'''
    for key, section in [('postinstall', 'post'), ('preremove', 'preun'), ('postremove', 'postun')]:
        if key in scripts:
            spec += '\n%' + section + '\n' + (ROOT / scripts[key]).read_text().replace('%', '%%') + '\n'
    spec += '\n%files\n' + '\n'.join(files) + '\n'
    spec_path = work / (name + '.spec')
    spec_path.write_text(spec)
    (work / 'tmp').mkdir()
    run('rpmbuild', '-bb', '--define', f'_topdir {work}',
        '--define', f'_rpmdir {OUTPUT.parent}', '--define', f'_tmppath {work}/tmp', spec_path)
    dist = subprocess.check_output(['rpm', '--eval', '%{?dist}'], text=True).strip()
    result = OUTPUT / f'{name}-{VERSION}-1{dist}.x86_64.rpm'
    run('rpm', '-K', result)
    (result.parent.parent / (result.name + '.sha256')).write_text(
        hashlib.sha256(result.read_bytes()).hexdigest() + '  x86_64/' + result.name + '\n')
    (result.parent.parent / (result.name + '.build.json')).write_text(json.dumps({
        'manifest': str(manifest.relative_to(ROOT)),
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'source_diff_sha256': hashlib.sha256(subprocess.check_output(['git', 'diff', 'HEAD'], cwd=ROOT)).hexdigest(),
        'payload_sha256': {str(p.relative_to(payload)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in payload.rglob('*') if p.is_file()},
    }, ensure_ascii=False, indent=2) + '\n')
    print(f'RPM ready: {result}')


if __name__ == '__main__':
    (ROOT / 'target/ui-rpms').mkdir(parents=True, exist_ok=True)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for component in ['gui', 'gnome-extension', 'cinnamon-extension', 'hyprlock', 'kde', 'omarchy']:
        package(ROOT / 'packaging' / f'nfpm-{component}.yaml')
