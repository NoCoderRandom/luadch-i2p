import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from guard import ALLOWED, Moderator, Unverified, extension, run, session_key

CID = 'A' * 39
HUB = 'adc://' + 'a' * 52 + '.b32.i2p'
USER = {'id': int.from_bytes(b'ABCD', 'little'), 'cid': CID,
        'flags': [], 'supports': ['IIPT']}


def item(name, directory='/', kind='file'):
    return {'name': name, 'type': {'id': kind},
            'path': directory + name + ('/' if kind == 'directory' else '')}


class Api:
    def __init__(self, tree):
        self.tree, self.directory = tree, '/'
        self.commands, self.calls = [], []
        self.present, self.loading, self.replace = True, False, False

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if '/users/' in path:
            return [dict(USER, cid='B' * 39) if self.replace else USER] if self.present else []
        if path.endswith('/chat_message'):
            self.commands.append(body['text'])
            self.present = False
        elif path == '/filelists':
            self.directory = '/'
        elif path.endswith('/directory'):
            self.directory = body['list_path']
        elif '/items/' in path:
            start, count = map(int, path.split('/')[-2:])
            return {'list_path': self.directory, 'items': self.tree[self.directory][start:start+count]}
        elif method == 'GET':
            return {'state': {'id': 'loading' if self.loading else 'loaded'}}


class GuardTests(unittest.TestCase):
    def make(self, tree, **kwargs):
        self.now = 0
        def sleep(seconds):
            self.now += seconds
        self.api = Api(tree)
        return Moderator(self.api, HUB, clock=lambda: self.now, sleep=sleep, **kwargs)

    def test_allowed_case_insensitive(self):
        for ext in ALLOWED:
            self.assertIn(extension('Example.' + ext.upper()), ALLOWED)

    def test_companions_allowed_not_general_documents(self):
        mod = self.make({'/': [item('Notes.TXT'), item('Tracks.m3u8'), item('Book.cue'),
                              item('Metadata.opf'), item('Checksum.sfv')]}, enforce=True)
        self.assertEqual(mod.check(1, USER).state, 'audio_names_only')
        for ext in ('pdf', 'epub', 'mobi', 'json', 'jsonl', 'log', 'py', 'bat'):
            self.assertNotIn(ext, ALLOWED)

    def test_allowed_tree_and_directory_suffix(self):
        mod = self.make({'/': [item('Folder.jpg', kind='directory')],
                         '/Folder.jpg/': [item('Book.M4B', '/Folder.jpg/')]}, enforce=True)
        self.assertEqual(mod.check(1, USER).state, 'audio_names_only')
        self.assertFalse(self.api.commands)

    def test_disallowed_types_and_double_extension(self):
        for name in ('cover.jpg', 'video.mkv', 'pack.zip', 'run.exe', 'readme',
                     'sound.mp3.exe', 'audio.mp4', 'sound.mp3 ', 'sound.mp3\u202e'):
            with self.subTest(name=name):
                mod = self.make({'/': [item(name)]}, enforce=True)
                self.assertEqual(mod.check(1, USER).state, 'disconnected')
                self.assertEqual(self.api.commands, ['+audiokick ABCD ' + CID])
                self.assertEqual(self.api.calls[-2][0], 'POST')

    def test_audit_default_never_kicks(self):
        mod = self.make({'/': [item('video.mkv')]})
        self.assertEqual(mod.check(1, USER).state, 'would_disconnect')
        self.assertFalse(self.api.commands)

    def test_pagination(self):
        mod = self.make({'/': [item(str(i) + '.mp3') for i in range(513)]}, enforce=True)
        self.assertEqual(mod.check(1, USER).files, 513)

    def test_stale_cid_never_kicks(self):
        mod = self.make({'/': [item('video.mkv')]}, enforce=True)
        self.api.replace = True
        self.assertEqual(mod.check(1, USER).state, 'stale')
        self.assertFalse(self.api.commands)

    def test_unavailable_is_not_a_violation(self):
        mod = self.make({'/': []}, enforce=True)
        self.api.loading = True
        with self.assertRaises(Unverified):
            mod.check(1, USER)
        self.assertFalse(self.api.commands)
        self.assertEqual(self.api.calls[-1][0], 'DELETE')

    def test_invalid_names_and_paths_never_kick(self):
        for name in ('..', '.', '../x.exe', 'x\n+disconnect admin', 'x\\y.exe', 'x\0.exe'):
            mod = self.make({'/': [item(name)]}, enforce=True)
            with self.assertRaises(Unverified):
                mod.check(1, USER)
            self.assertFalse(self.api.commands)
        bad = item('safe.mp3')
        bad['path'] = '/other/safe.mp3'
        mod = self.make({'/': [bad]}, enforce=True)
        with self.assertRaises(Unverified):
            mod.check(1, USER)

    def test_scan_limits(self):
        mod = self.make({'/': [item('ok.mp3'), item('video.mkv')]}, enforce=True, max_items=1)
        with self.assertRaises(Unverified):
            mod.check(1, USER)
        self.assertFalse(self.api.commands)

    def test_directory_limits(self):
        mod = self.make({'/': [item('one', kind='directory')]}, enforce=True, max_dirs=1)
        with self.assertRaises(Unverified):
            mod.check(1, USER)

    def test_protected_and_unsupported(self):
        mod = self.make({'/': [item('video.mkv')]}, enforce=True)
        for flag in ('self', 'op'):
            self.assertEqual(mod.check(1, dict(USER, flags=[flag])).state, 'protected')
        self.assertEqual(mod.check(1, dict(USER, supports=[])).state, 'unverified')
        self.assertFalse(self.api.calls)

    def test_bot_flag_not_an_exemption(self):
        mod = self.make({'/': [item('video.mkv')]}, enforce=True)
        self.assertEqual(mod.check(1, dict(USER, flags=['bot'])).state, 'disconnected')

    def test_identity_and_url_validation(self):
        for url in ('adc://example.com', 'adc://127.0.0.1', HUB + ':1511', 'http://example.com'):
            with self.assertRaises(ValueError):
                Moderator(None, url)
        for key, value in (('cid', '../bad'), ('id', -1), ('id', 0), ('id', True)):
            with self.assertRaises(Unverified):
                session_key(dict(USER, **{key: value}))

    def test_fresh_scan_and_cleanup(self):
        mod = self.make({'/': [item('ok.mp3')]})
        mod.check(1, USER)
        self.api.tree['/'] = [item('new.jpg')]
        self.assertEqual(mod.check(1, USER).state, 'would_disconnect')
        self.assertEqual(sum(c[0] == 'DELETE' for c in self.api.calls), 2)

    def test_runtime_download_directory_is_outside_private_profile(self):
        seen = {}
        class Runtime:
            def __init__(self, state, package):
                self.state, self.config = state, {}
                seen['runtime'] = self
            def save(self):
                pass
            def start(self):
                destination = Path(self.config['downloads'])
                self_test.assertNotEqual(destination, self.state)
                self_test.assertNotIn(self.state, destination.parents)
                raise KeyboardInterrupt
            def close(self):
                seen['closed'] = True
        self_test = self
        fake = SimpleNamespace(Runtime=Runtime, ClientError=RuntimeError,
            read_json=lambda _: {'hub_url': HUB, 'nick': 'AudioGuard', 'password': 'fixture'},
            write_json=lambda path, data: seen.update(status=data))
        with patch.dict('sys.modules', runtime=fake), patch('guard.signal.signal'), patch('sys.path', []):
            run(SimpleNamespace(config='private/settings.json', enforce=False))
        self.assertTrue(seen['closed'])
        self.assertEqual(seen['status']['state'], 'offline')


if __name__ == '__main__':
    unittest.main()
