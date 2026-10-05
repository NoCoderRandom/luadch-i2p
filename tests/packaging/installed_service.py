#!/usr/bin/python3
"""Root-only delta test. Run ONLY in a disposable Linux VM with this package."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

DATA = Path('/var/lib/luadch-i2p')
STATE = Path('/run/luadch-i2p/status.json')


def service(action):
    subprocess.run(['systemctl', action, 'luadch-i2p.service'], check=True)


def wait_until(predicate, description, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.25)
    raise AssertionError('Timed out: ' + description)


def sam_active():
    try:
        return json.loads(STATE.read_text())['state'].startswith('SAM active')
    except (FileNotFoundError, json.JSONDecodeError):
        return False


def processes():
    pid = int(subprocess.check_output(['systemctl', 'show', 'luadch-i2p', '-p', 'MainPID', '--value']))
    children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
    return {Path(f'/proc/{child}/exe').resolve().name: int(child) for child in children}


def assert_local_only(pid):
    handles = {os.readlink(fd) for fd in Path(f'/proc/{pid}/fd').iterdir()}
    count = 0
    for protocol in ('tcp', 'tcp6', 'udp', 'udp6'):
        for row in Path('/proc/net/' + protocol).read_text().splitlines()[1:]:
            fields = row.split()
            if 'socket:[' + fields[9] + ']' not in handles:
                continue
            count += 1
            assert protocol == 'tcp', 'Unexpected UDP or IPv6 DC socket'
            assert fields[1].split(':')[0] == '0100007F', 'Non-loopback DC bind'
            assert fields[2].split(':')[0] in ('0100007F', '00000000'), 'Non-loopback DC peer'
    assert count > 0, 'No inspected DC socket'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    parser.add_argument('--case', choices=('all', 'orderly-stop'), default='all')
    args = parser.parse_args()
    assert os.geteuid() == 0
    subprocess.run(['systemd-detect-virt', '--vm', '--quiet'], check=True)
    try:
        service('start')
        wait_until(sam_active, 'initial local SAM registration')
        identity = (DATA / 'cfg/i2p-hub.private').read_bytes()
        address = (DATA / 'hub-address').read_bytes()
        assert (DATA / 'cfg/i2p-hub.private').stat().st_mode & 0o777 == 0o600
        assert (DATA / 'setup.txt').stat().st_uid == 0
        original = processes()
        assert set(original) == {'i2pd', 'luadch', 'luadch-i2p-forward'}
        assert_local_only(original['luadch'])
        assert_local_only(original['luadch-i2p-forward'])
        print('PASS: owned router, local SAM, local-only DC sockets and private state', flush=True)

        service('stop')
        assert all(not Path(f'/proc/{pid}').exists() for pid in original.values())
        assert not STATE.exists()
        stopped = subprocess.check_output([
            'systemctl', 'show', 'luadch-i2p', '-p', 'ActiveState', '-p', 'Result', '-p', 'ExecMainStatus'
        ], text=True).splitlines()
        assert set(stopped) == {'ActiveState=inactive', 'Result=success', 'ExecMainStatus=0'}, stopped
        print('PASS: manual stop reports inactive/success and leaves no children', flush=True)
        if args.case == 'orderly-stop':
            return
        service('start')
        wait_until(sam_active, 'restart local SAM registration')
        assert (DATA / 'cfg/i2p-hub.private').read_bytes() == identity
        assert (DATA / 'hub-address').read_bytes() == address
        print('PASS: orderly stop, no leftover children, restart preserves identity', flush=True)

        old = processes()
        os.kill(old['i2pd'], signal.SIGTERM)
        wait_until(lambda: all(not Path(f'/proc/{pid}').exists() for pid in old.values()),
                   'router loss takes old hub and forwarder offline', timeout=35)
        wait_until(sam_active, 'systemd recovery with same identity')
        assert (DATA / 'cfg/i2p-hub.private').read_bytes() == identity
        assert (DATA / 'hub-address').read_bytes() == address
        restored = processes()
        assert_local_only(restored['luadch'])
        assert_local_only(restored['luadch-i2p-forward'])
        print('PASS: managed router loss, whole-service recovery and local-only DC sockets', flush=True)
    finally:
        service('stop')
    print('Service left stopped. This test does not claim remote I2P reachability.', flush=True)


if __name__ == '__main__':
    main()
