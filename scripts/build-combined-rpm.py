#!/usr/bin/env python3
"""Build one Fedora RPM containing Gaze PAM fixes and the private KRDP repair."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def output(*args):
    return subprocess.check_output([str(a) for a in args], text=True).strip()


def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-rpm', required=True, type=Path, help='Official or previously built gaze x86_64 RPM matching Cargo.toml')
    parser.add_argument('--release', default='1')
    parser.add_argument('--reuse-krdp-build', action='store_true', help='Use the tested target/krdp-fix artifact, checking its build manifest')
    parser.add_argument('--deps-root', type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.]+', args.release):
        raise SystemExit('Invalid RPM release')
    base = args.base_rpm.resolve()
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    if output('rpm', '-qp', '--qf', '%{NAME} %{VERSION} %{ARCH}', base) != f'gaze {version} x86_64':
        raise SystemExit('Base RPM must be gaze of the same source version, x86_64')
    if output('rpm', '-qp', '--qf', '%{FILEDIGESTALGO}', base) != '8':
        raise SystemExit('Base RPM must use SHA256 payload digests')
    run('rpm', '-K', base)
    run('cargo', 'build', '--release', '--locked', '-p', 'gazed', cwd=ROOT)
    run('cargo', 'build', '--release', '--locked', '-p', 'gaze-cli', '-p', 'gaze-gui',
        '-p', 'pam-gaze', '-p', 'pam-gaze-grosshack', cwd=ROOT)
    run('cargo', 'test', '--locked', '-p', 'pam-gaze', cwd=ROOT)
    run(ROOT / 'scripts/check-pam-link.sh', ROOT / 'target/release/libpam_gaze.so')
    if not args.reuse_krdp_build:
        command = [sys.executable, str(ROOT / 'scripts/build-krdp-fix.py')]
        if args.deps_root:
            command += ['--deps-root', str(args.deps_root.resolve())]
        run(*command)
    library = ROOT / 'target/krdp-fix/libKRdp.so.6.7.5'
    build_info = json.loads((library.parent / 'build-info.json').read_text())
    if hashlib.sha256(library.read_bytes()).hexdigest() != build_info['library_sha256']:
        raise SystemExit('KRDP artifact differs from the tested build manifest')
    source_root = ROOT / 'third_party/krdp'
    current_meta = json.loads((source_root / 'UPSTREAM.json').read_text())
    inputs = [source_root / current_meta['archive'], source_root / 'CMakeLists.txt',
              *(source_root / p for p in current_meta['patches']), *sorted((source_root / 'tests').glob('*.cpp'))]
    if hashlib.sha256(b''.join(p.read_bytes() for p in inputs)).hexdigest()[:16] != build_info['input_fingerprint']:
        raise SystemExit('KRDP sources changed since the tested build; rebuild without --reuse-krdp-build')
    metadata = output('rpm', '-qp', '--qf', '[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEMODES}\t%{FILEFLAGS}\n]', base)
    records = [line.split('\t') for line in metadata.splitlines()]
    for name, *_ in records:
        if not name.startswith('/') or '..' in Path(name).parts:
            raise SystemExit('Unsafe path in base RPM')
    work_parent = ROOT / 'target/combined-rpm'
    work_parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='build-', dir=work_parent))
    payload = work / 'payload'
    payload.mkdir()
    extract = subprocess.Popen(['rpm2cpio', str(base)], stdout=subprocess.PIPE)
    unpack = subprocess.run(['cpio', '-idm', '--quiet', '--no-absolute-filenames', '--no-preserve-owner'], stdin=extract.stdout, cwd=payload)
    extract.stdout.close()
    if unpack.returncode or extract.wait():
        raise SystemExit('Failed to extract base RPM')
    config_files = set()
    for name, digest, mode, flags in records:
        p = payload / name.lstrip('/')
        if p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            raise SystemExit(f'Base payload checksum mismatch: {name}')
        if int(flags) & 1:
            config_files.add(name)
        if not p.is_symlink():
            p.chmod(stat.S_IMODE(int(mode)))

    def stage(src, destination, mode=0o644):
        dest = payload / destination.lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        dest.chmod(mode)
        return dest

    stage(ROOT / 'target/release/gazed', '/usr/bin/gazed', 0o755)
    stage(ROOT / 'target/release/gaze', '/usr/bin/gaze', 0o755)
    stage(ROOT / 'target/release/libpam_gaze_grosshack.so', '/usr/lib64/security/pam_gaze_grosshack.so', 0o755)
    stage(ROOT / 'packaging/config/com.gundulabs.gaze.policy', '/usr/share/polkit-1/actions/com.gundulabs.gaze.policy')
    stage(ROOT / 'target/release/libpam_gaze.so', '/usr/lib64/security/pam_gaze.so', 0o755)
    stage(ROOT / 'packaging/config/config.toml', '/etc/gaze/config.toml')
    stage(ROOT / 'packaging/config/com.gundulabs.Gaze.conf', '/etc/dbus-1/system.d/com.gundulabs.Gaze.conf')
    private = stage(library, '/usr/lib64/gaze-krdp-fix/6.7.5/libKRdp.so.6', 0o755)
    run('strip', '--strip-debug', private)
    stage(ROOT / 'packaging/krdp-fix/gaze-krdp-server', '/usr/libexec/gaze-krdp-server', 0o755)
    stage(ROOT / 'packaging/krdp-fix/90-gaze-krdp-fix.conf', '/usr/lib/systemd/user/app-org.kde.krdpserver.service.d/90-gaze-krdp-fix.conf')
    stage(ROOT / 'docs/krdp-fix.md', '/usr/share/doc/gaze/krdp-fix/README.md')
    stage(ROOT / 'LICENSE', '/usr/share/licenses/gaze/LICENSE')
    for p in (ROOT / 'third_party/krdp').rglob('*'):
        if p.is_file():
            stage(p, '/usr/share/doc/gaze/krdp-fix/source/' + str(p.relative_to(ROOT / 'third_party/krdp')))
    stage(ROOT / 'scripts/build-krdp-fix.py', '/usr/share/doc/gaze/krdp-fix/build-krdp-fix.py')
    extra_dirs = ['/usr/lib64/gaze-krdp-fix', '/usr/lib64/gaze-krdp-fix/6.7.5']
    file_lines = ['%dir ' + p for p in extra_dirs]
    for p in sorted(payload.rglob('*')):
        if p.is_dir():
            continue
        name = '/' + str(p.relative_to(payload))
        flags = '%config(noreplace) ' if name in config_files else ''
        file_lines.append(f'{flags}%attr({stat.S_IMODE(p.lstat().st_mode):04o},root,root) {name}')
    requirements = {line for line in output('rpm', '-qpR', base).splitlines()
                    if not line.startswith(('rpmlib(', 'config(gaze)', 'gaze =', 'gaze(x86-64)'))}
    requirements.add('krdp')
    hook = (ROOT / 'packaging/krdp-fix/refresh-user-services.sh').read_text().replace('%', '%%')
    post = (ROOT / 'packaging/postinst-rpm.sh').read_text().replace('%', '%%')
    preun = (ROOT / 'packaging/prerm-rpm.sh').read_text().replace('%', '%%')
    spec = '''%global debug_package %{nil}
%global __os_install_post %{nil}
%global __provides_exclude_from ^/usr/lib(64)?/(gaze|gaze-krdp-fix)/.*$
%global __requires_exclude ^libonnxruntime\\.so.*$
Name: gaze
Version: ''' + version + '\nRelease: ' + args.release + '''%{?dist}
Summary: Gaze Chinese PAM and KRDP login, frame acknowledgement fixes
License: GPL-3.0-or-later AND GPL-2.0-or-later AND BSD-2-Clause AND BSD-3-Clause AND LGPL-2.0-or-later AND (LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL)
URL: https://github.com/GunduLabs/gaze
Vendor: Local gaze-zh-rdp-fix build
BuildArch: x86_64
Provides: bundled(krdp) = 6.7.5
Requires(posttrans): systemd
Requires(postun): systemd
''' + ''.join('Requires: ' + r + '\n' for r in sorted(requirements)) + '''
%description
Gaze with Chinese interfaces and the KRDP network-login fix.
The daemon, CLI, PAM modules and private KRDP library are rebuilt from this
project. Runtime libraries and support files use the verified base RPM payload.
The KRDP service wrapper enables the private repair only for its supported
Fedora KRDP build, without replacing the distribution's system library.
Windows App Android users should disable hardware decoding in the client.

%prep
%build
%install
mkdir -p %{buildroot}
cp -a "%{_topdir}/payload/." %{buildroot}/

%post
''' + post + '\n%preun\n' + preun + '\n%posttrans\n' + hook + '\n%postun\nif [ "$1" -eq 0 ]; then\n' + hook + '\nfi\n\n%files\n' + '\n'.join(file_lines) + '\n'
    spec_path = work / 'gaze-combined.spec'
    spec_path.write_text(spec)
    packages = ROOT / 'dist/packages'
    packages.mkdir(parents=True, exist_ok=True)
    (work / 'tmp').mkdir()
    run('rpmbuild', '-bb', '--define', f'_topdir {work}', '--define', f'_rpmdir {packages}',
        '--define', f'_tmppath {work}/tmp', spec_path)
    release = args.release + output('rpm', '--eval', '%{?dist}')
    rpm = packages / 'x86_64' / f'gaze-{version}-{release}.x86_64.rpm'
    run('rpm', '-K', rpm)
    # All requirements must be available on this build host or provided by the RPM itself.
    provides = set(output('rpm', '-qp', '--provides', rpm).splitlines())
    for requirement in output('rpm', '-qpR', rpm).splitlines():
        if requirement.startswith('rpmlib(') or requirement in provides:
            continue
        run('rpm', '-q', '--whatprovides', requirement, stdout=subprocess.DEVNULL)
    (packages / (rpm.name + '.sha256')).write_text(hashlib.sha256(rpm.read_bytes()).hexdigest() + '  x86_64/' + rpm.name + '\n')
    (packages / (rpm.name + '.build.json')).write_text(json.dumps({
        'base_rpm': base.name, 'base_sha256': hashlib.sha256(base.read_bytes()).hexdigest(),
        'gaze_source_commit': output('git', '-C', ROOT, 'rev-parse', 'HEAD'),
        'source_diff_sha256': hashlib.sha256(subprocess.check_output(['git', '-C', str(ROOT), 'diff', 'HEAD'])).hexdigest(),
        'binaries_sha256': {name: hashlib.sha256((ROOT / 'target/release' / name).read_bytes()).hexdigest()
                            for name in ['gazed', 'gaze', 'libpam_gaze.so', 'libpam_gaze_grosshack.so']},
        'krdp_build': build_info, 'spec': str(spec_path.relative_to(ROOT)),
        'validation': 'PAM tests, KRDP tests, RPM digests, dependencies passed',
    }, indent=2) + '\n')
    print(f'Combined RPM ready: {rpm}')


if __name__ == '__main__':
    main()
