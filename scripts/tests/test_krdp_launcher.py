"""Exercise the packaged wrapper without touching the live KRDP service."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LauncherTests(unittest.TestCase):
    def launch(self, package):
        with tempfile.TemporaryDirectory() as temporary:
            d = Path(temporary)
            (d / 'rpm').write_text('#!/bin/sh\nprintf "%s" "$TEST_RPM_VERSION"\n')
            server = d / 'server'
            server.write_text('''#!/bin/sh
printf '%s\\n' "${LD_LIBRARY_PATH-unset}" "${KRDP_DISABLE_H264-unset}" "${KPIPEWIRE_FORCE_ENCODER-unset}" "$WLOG_LEVEL" "$QT_LOGGING_RULES" "$@"
''')
            (d / 'rpm').chmod(0o755)
            server.chmod(0o755)
            source = (ROOT / 'packaging/krdp-fix/gaze-krdp-server').read_text()
            wrapper = d / 'wrapper'
            wrapper.write_text(source.replace('/usr/bin/krdpserver', str(server)))
            env = dict(os.environ, PATH=str(d) + os.pathsep + os.environ['PATH'], TEST_RPM_VERSION=package,
                       LD_LIBRARY_PATH='/old/user/repair', KRDP_DISABLE_H264='1', KPIPEWIRE_FORCE_ENCODER='stale')
            return subprocess.run(['sh', str(wrapper), '--example', 'argument with spaces'], env=env, text=True, capture_output=True, check=True)

    def test_matching_version_loads_packaged_library(self):
        result = self.launch('6.7.5-1.fc44.x86_64')
        self.assertEqual(result.stdout.splitlines(), ['/usr/lib64/gaze-krdp-fix/6.7.5', 'unset', 'unset', 'WARN', '*.debug=false', '--example', 'argument with spaces'])
        self.assertEqual(result.stderr, '')

    def test_future_version_uses_system_library(self):
        result = self.launch('6.8.0-1.fc44.x86_64')
        self.assertEqual(result.stdout.splitlines()[0], 'unset')
        self.assertIn('using the system library', result.stderr)

    def test_other_release_uses_system_library(self):
        self.assertEqual(self.launch('6.7.5-2.fc44.x86_64').stdout.splitlines()[0], 'unset')

    def test_missing_package_does_not_keep_old_override(self):
        self.assertEqual(self.launch('').stdout.splitlines()[:3], ['unset', 'unset', 'unset'])


if __name__ == '__main__':
    unittest.main()
