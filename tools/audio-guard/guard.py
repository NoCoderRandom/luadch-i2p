#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Filename-policy moderator using the installed, owned I2P-only Linux runtime."""
import argparse
from collections import deque
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import signal
import sys
import time

AUDIO = frozenset('aa aac aax aif aiff alac ape flac m4a m4b mka mp3 oga ogg opus wav wave wma wv'.split())
COMPANIONS = frozenset('txt nfo m3u m3u8 pls cue sfv opf lrc'.split())
ALLOWED = AUDIO | COMPANIONS
CID = re.compile(r'[A-Z2-7]{39}\Z')
HUB = re.compile(r'adc://[a-z2-7]{52}\.b32\.i2p\Z')
PAGE = 256


class Unverified(Exception):
    """Insufficient evidence; never a reason for a filename-policy kick."""


@dataclass
class Result:
    state: str
    files: int = 0
    extension: str = ''


def extension(name):
    if (not isinstance(name, str) or not name or len(name) > 1024 or
            any(c in name for c in '/\\\x00\r\n') or name in ('.', '..')):
        raise Unverified('invalid name')
    return name.rsplit('.', 1)[-1].lower() if '.' in name else ''


def session_key(user):
    cid = user.get('cid', '')
    number = user.get('id')
    if not isinstance(cid, str) or not CID.fullmatch(cid) or type(number) is not int:
        raise Unverified('invalid user')
    try:
        sid = number.to_bytes(4, 'little').decode('ascii')
    except (OverflowError, UnicodeError):
        raise Unverified('invalid session') from None
    if not re.fullmatch('[A-Z2-7]{4}', sid):
        raise Unverified('invalid session')
    return sid, cid


class Moderator:
    def __init__(self, api, hub_url, enforce=False, clock=time.monotonic,
                 sleep=time.sleep, max_items=250000, max_dirs=10000, scan_seconds=3600):
        if not HUB.fullmatch(hub_url):
            raise ValueError('Only a portless I2P hub destination is allowed')
        self.api, self.hub_url, self.enforce = api, hub_url, enforce
        self.clock, self.sleep = clock, sleep
        self.max_items, self.max_dirs, self.scan_seconds = max_items, max_dirs, scan_seconds

    def users(self, hub_id):
        result = []
        for start in range(0, 4096, PAGE):
            page = self.api.request('GET', f'/hubs/{hub_id}/users/{start}/{PAGE}')
            if not isinstance(page, list) or len(page) > PAGE:
                raise Unverified('invalid user page')
            result.extend(page)
            if len(page) < PAGE:
                return result
        raise Unverified('user limit reached')

    def current(self, hub_id, expected):
        key = session_key(expected)
        return next((u for u in self.users(hub_id) if (u.get('id'), u.get('cid')) ==
                     (expected['id'], key[1])), None)

    def loaded(self, path, directory, deadline):
        end = min(deadline, self.clock() + 240)
        while self.clock() < end:
            status = self.api.request('GET', path)
            state = status.get('state', {}).get('id')
            if state in ('failed', 'download_failed'):
                raise Unverified('list unavailable')
            if state == 'loaded':
                try:
                    page = self.api.request('GET', path + f'/items/0/{PAGE}')
                    if page.get('list_path') == directory:
                        return page
                except Exception as error:
                    if getattr(error, 'status', None) != 503:
                        raise
            self.sleep(2)
        raise Unverified('list timeout')

    def scan(self, user):
        _, cid = session_key(user)
        path = '/filelists/' + cid
        deadline = self.clock() + self.scan_seconds
        opened = False
        files = total = 0
        try:
            self.api.request('POST', '/filelists', {
                'user': {'cid': cid, 'hub_url': self.hub_url}})
            opened = True
            pending, visited = deque(['/']), set()
            while pending:
                if self.clock() >= deadline or len(visited) >= self.max_dirs:
                    raise Unverified('scan limit reached')
                directory = pending.popleft()
                if directory in visited:
                    raise Unverified('duplicate directory')
                visited.add(directory)
                if directory != '/':
                    self.api.request('POST', path + '/directory', {'list_path': directory, 'reload': True})
                page = self.loaded(path, directory, deadline)
                start = 0
                while True:
                    if self.clock() >= deadline or page.get('list_path') != directory:
                        raise Unverified('directory changed')
                    items = page.get('items')
                    if not isinstance(items, list) or len(items) > PAGE:
                        raise Unverified('invalid file page')
                    for item in items:
                        total += 1
                        if total > self.max_items:
                            raise Unverified('item limit reached')
                        name = item.get('name')
                        ext = extension(name)
                        kind = item.get('type', {}).get('id')
                        expected = directory + name + ('/' if kind == 'directory' else '')
                        if item.get('path') != expected:
                            raise Unverified('invalid path')
                        if kind == 'directory':
                            if len(pending) + len(visited) >= self.max_dirs or len(expected) > 4096:
                                raise Unverified('directory limit reached')
                            pending.append(expected)
                        elif kind == 'file':
                            files += 1
                            if ext not in ALLOWED:
                                # Never return names/paths to logs, chat or control commands.
                                safe_ext = ext if re.fullmatch('[a-z0-9]{1,12}', ext) else 'other'
                                return Result('violation', files, safe_ext)
                        else:
                            raise Unverified('unknown item type')
                    if len(items) < PAGE:
                        break
                    start += PAGE
                    page = self.api.request('GET', path + f'/items/{start}/{PAGE}')
            return Result('audio_names_only', files)
        finally:
            if opened:
                self.api.request('DELETE', path)

    def check(self, hub_id, user):
        if set(user.get('flags', [])) & {'self', 'op'}:
            return Result('protected')
        if 'IIPT' not in user.get('supports', []):
            return Result('unverified')
        session_key(user)
        result = self.scan(user)
        if result.state != 'violation':
            return result
        if not self.current(hub_id, user):
            return Result('stale')
        if not self.enforce:
            return Result('would_disconnect', result.files, result.extension)
        sid, cid = session_key(user)
        self.api.request('POST', f'/hubs/{hub_id}/chat_message',
                         {'text': f'+audiokick {sid} {cid}'})
        for _ in range(10):
            self.sleep(1)
            if not self.current(hub_id, user):
                return Result('disconnected', result.files, result.extension)
        return Result('disconnect_unconfirmed', result.files, result.extension)


def run(args):
    # The installed runtime pins both SAM and API sockets to its own children.
    sys.path.insert(0, '/usr/lib/airdc-i2p')
    from runtime import Runtime, ClientError, read_json, write_json
    settings = read_json(args.config)
    if not HUB.fullmatch(settings['hub_url']):
        raise ValueError('Invalid I2P hub URL')
    runtime = Runtime(Path(args.config).parent / 'profile', '/usr/lib/airdc-i2p')
    runtime.config.update(nick=settings['nick'], downloads=str(Path(args.config).parent / 'unused-downloads'))
    runtime.save()
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    status_path = Path(args.config).parent / 'status.json'
    try:
        runtime.start()
        api = runtime.api
        if api.request('GET', '/share_roots'):
            raise ClientError('Moderator profile must not share any files')
        favorites = api.request('GET', '/favorite_hubs/0/100')
        if not favorites:
            api.request('POST', '/favorite_hubs', {
                'name': 'Audio moderation', 'hub_url': settings['hub_url'],
                'password': settings['password'], 'auto_connect': True})
        elif len(favorites) != 1 or favorites[0]['hub_url'] != settings['hub_url']:
            raise ClientError('Moderator must have exactly one configured hub')
        if not api.request('GET', '/hubs'):
            api.request('POST', '/hubs', {'hub_url': settings['hub_url']})
        moderator = Moderator(api, settings['hub_url'], args.enforce)
        due = {}
        previous_state = None
        while True:
            runtime.check()
            hubs = api.request('GET', '/hubs')
            if any(h.get('hub_url') != settings['hub_url'] for h in hubs):
                raise ClientError('Unexpected hub in moderator profile')
            hub = next((h for h in hubs if h['connect_state']['id'] == 'connected'), None)
            state = 'active' if hub else 'connecting'
            if state != previous_state:
                print('AudioGuard: ' + state, flush=True)
                write_json(status_path, {'state': state, 'enforce': args.enforce})
                previous_state = state
            if not hub:
                time.sleep(10)
                continue
            users = moderator.users(hub['id'])
            active = {(u.get('id'), u.get('cid')) for u in users}
            due = {key: value for key, value in due.items() if key in active}
            for user in users:
                if set(user.get('flags', [])) & {'self', 'op'}:
                    continue
                key = (user.get('id'), user.get('cid'))
                if due.get(key, 0) > time.monotonic():
                    continue
                try:
                    result = moderator.check(hub['id'], user)
                except (Unverified, ClientError, ValueError, KeyError, TypeError, OSError):
                    runtime.check()
                    result = Result('unverified')
                fingerprint = hashlib.sha256(str(user.get('cid', '')).encode()).hexdigest()[:12]
                record = {'peer': fingerprint, 'state': result.state, 'files': result.files,
                          'extension': result.extension}
                print(json.dumps(record, sort_keys=True), flush=True)
                write_json(status_path, {'state': 'active', 'enforce': args.enforce, 'last_check': record})
                due[key] = time.monotonic() + (1800 if result.state == 'audio_names_only' else 300)
            time.sleep(15)
    except KeyboardInterrupt:
        pass
    except Exception:
        import traceback
        write_json(Path(args.config).parent / 'error.private.json', {'traceback': traceback.format_exc()})
        raise
    finally:
        runtime.close()
        write_json(status_path, {'state': 'offline', 'enforce': args.enforce})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--enforce', action='store_true', help='Request kicks for confirmed filename violations')
    try:
        run(parser.parse_args())
    except Exception:
        # Do not put credential-bearing configuration, peer names or API data in journal.
        print('AudioGuard: stopped on error; check private configuration and service state.', file=sys.stderr)
        raise SystemExit(1)
