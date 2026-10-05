import importlib.util
import os
from pathlib import Path
import socket
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / 'packaging/debian' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


manage = module('manage')
prepare = module('prepare')


class PackageHelpers(unittest.TestCase):
    def test_stop_signal_racing_child_eof_or_exit(self):
        for event in ('stop-eof', 'stop-exit', 'unexpected-eof', 'unexpected-exit'):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as directory:
                handlers = {}
                router, hub, forward = Mock(), Mock(), Mock()
                children = (router, hub, forward)
                for child in children:
                    child.poll.return_value = None
                selector = Mock()

                def select(**_kwargs):
                    if event == 'stop-eof':
                        handlers[signal.SIGTERM](signal.SIGTERM, None)
                    return [(SimpleNamespace(fd=123), None)]

                def poll():
                    if event == 'stop-exit':
                        handlers[signal.SIGTERM](signal.SIGTERM, None)
                    return 1

                selector.select.side_effect = select
                if event.endswith('exit'):
                    # The first poll occurs during startup, before wait_owned returns.
                    calls = iter([None])
                    def router_poll():
                        try:
                            return next(calls)
                        except StopIteration:
                            return poll()
                    router.poll.side_effect = router_poll
                with patch.object(manage, 'RUN', Path(directory)), \
                        patch.object(manage.os, 'umask'), \
                        patch.object(manage, 'free_port', return_value=1234), \
                        patch.object(manage, 'owns_listener', return_value=True), \
                        patch.object(manage.signal, 'signal', side_effect=lambda sig, fn: handlers.update({sig: fn})), \
                        patch.object(manage.subprocess, 'Popen', side_effect=children), \
                        patch.object(manage.selectors, 'DefaultSelector', return_value=selector), \
                        patch.object(manage.os, 'read', return_value=b''):
                    if event.startswith('stop-'):
                        manage.run_service()
                    else:
                        with self.assertRaises(RuntimeError):
                            manage.run_service()
                for child in children:
                    child.wait.assert_called_once()
                self.assertFalse((Path(directory) / 'status.json').exists())

    def test_owned_listener_not_just_open_port(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            port = listener.getsockname()[1]
            self.assertTrue(manage.owns_listener(os.getpid(), port))
            self.assertFalse(manage.owns_listener(999999999, port))
        self.assertFalse(manage.owns_listener(os.getpid(), port))

    def test_atomic_private_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state'
            manage.atomic_text(path, 'first')
            manage.atomic_text(path, 'second')
            self.assertEqual(path.read_text(), 'second')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_forwarder_address_filter(self):
        prefix = 'I2P hub destination: '
        self.assertIsNotNone(manage.ADDRESS_LINE.fullmatch(prefix + 'a' * 52 + '.b32.i2p'))
        for value in ('127.0.0.1', '[::1]', 'x.b32.i2p', 'a' * 52 + '.b32.i2p\nextra'):
            self.assertIsNone(manage.ADDRESS_LINE.fullmatch(prefix + value))

    def test_private_initialization_reinstall_and_interrupted_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'program'
            data = Path(directory) / 'state'
            (root / 'defaults').mkdir(parents=True)
            (root / 'defaults/cfg.tbl').write_text('return {}')
            (root / 'hub/lib/luadch').mkdir(parents=True)
            (root / 'hub/lib/luadch/ca-bundle.pem').write_text('test certificate')
            account = type('Account', (), {'pw_uid': os.getuid(), 'pw_gid': os.getgid()})()
            with patch.object(prepare, 'ROOT', root), patch.object(prepare, 'DATA', data), \
                    patch.object(prepare.pwd, 'getpwnam', return_value=account):
                prepare.main()
                users = (data / 'cfg/user.tbl').read_bytes()
                credentials = (data / 'setup.txt').read_bytes()
                self.assertIn(b'nick="admin"', users)
                self.assertNotIn(b'password="test"', users)
                self.assertEqual((data / 'setup.txt').stat().st_mode & 0o777, 0o600)
                (data / 'cfg/i2p-hub.private').write_bytes(b'identity fixture')
                (data / 'cfg/cfg.tbl').write_text('custom configuration')
                prepare.main()
                self.assertEqual((data / 'cfg/user.tbl').read_bytes(), users)
                self.assertEqual((data / 'cfg/cfg.tbl').read_text(), 'custom configuration')
                self.assertEqual((data / 'cfg/i2p-hub.private').read_bytes(), b'identity fixture')
                (data / 'cfg/user.tbl').unlink()
                prepare.main()
                self.assertEqual((data / 'setup.txt').read_bytes(), credentials)
                self.assertEqual((data / 'cfg/user.tbl').read_bytes(), users)

    def test_runtime_directory_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'state').symlink_to(root, target_is_directory=True)
            account = type('Account', (), {'pw_uid': os.getuid(), 'pw_gid': os.getgid()})()
            with patch.object(prepare, 'DATA', root / 'state'), \
                    patch.object(prepare.pwd, 'getpwnam', return_value=account):
                with self.assertRaisesRegex(SystemExit, 'symlink'):
                    prepare.main()


if __name__ == '__main__':
    unittest.main()
