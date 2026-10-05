#!/usr/bin/python3
"""Local service lifecycle for the Debian PoC. No remote management endpoint."""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import tempfile
import time

ROOT = Path('/usr/lib/luadch-i2p')
DATA = Path('/var/lib/luadch-i2p')
RUN = Path('/run/luadch-i2p')
ADDRESS_LINE = re.compile(r'I2P hub destination: ([a-z2-7]{52}\.b32\.i2p)\Z')


def atomic_text(path, text):
    fd, name = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def owns_listener(pid, port):
    """Check the listening socket inode, not merely whether a port answers."""
    sockets = set()
    try:
        for fd in Path(f'/proc/{pid}/fd').iterdir():
            try:
                sockets.add(os.readlink(fd))
            except FileNotFoundError:
                pass
        for row in Path('/proc/net/tcp').read_text().splitlines()[1:]:
            fields = row.split()
            if (fields[1] == f'0100007F:{port:04X}' and fields[3] == '0A'
                    and f'socket:[{fields[9]}]' in sockets):
                return True
    except FileNotFoundError:
        pass
    return False


def run_service():
    os.umask(0o077)
    children = []
    stopping = False
    state_file = RUN / 'status.json'
    selector = selectors.DefaultSelector()

    def status(state):
        atomic_text(state_file, json.dumps({'state': state}) + '\n')
        print('Luadch-I2P: ' + state, flush=True)

    def stop_requested(_signal, _frame):
        nonlocal stopping
        stopping = True

    def start(command, capture=False):
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE if capture else None,
                                 stderr=None, close_fds=True)
        children.append(child)
        return child

    def wait_owned(child, port):
        deadline = time.monotonic() + 60
        while not stopping:
            if child.poll() is not None:
                raise RuntimeError('A managed process exited during startup')
            if owns_listener(child.pid, port):
                return
            if time.monotonic() >= deadline:
                raise RuntimeError('Managed local listener did not start; refusing another service')
            time.sleep(0.2)

    signal.signal(signal.SIGTERM, stop_requested)
    signal.signal(signal.SIGINT, stop_requested)
    try:
        status('Starting')
        sam_port = free_port(socket.SOCK_STREAM)
        udp_port = free_port(socket.SOCK_DGRAM)
        router = start([
            str(ROOT / 'router/i2pd'),
            '--conf=' + str(ROOT / 'i2pd.conf'), '--datadir=' + str(DATA / 'router'),
            '--certsdir=' + str(ROOT / 'router/certificates'),
            '--tunconf=' + str(ROOT / 'tunnels.conf'),
            '--tunnelsdir=' + str(ROOT / 'tunnels.d'),
            '--pidfile=' + str(RUN / 'i2pd.pid'),
            '--sam.port=' + str(sam_port), '--sam.portudp=' + str(udp_port),
        ])
        wait_owned(router, sam_port)
        if stopping:
            return
        hub = start([str(ROOT / 'hub/luadch')])
        wait_owned(hub, 17650)
        if stopping:
            return
        # Recheck router ownership immediately before handing its port to SAM.
        if not owns_listener(router.pid, sam_port):
            raise RuntimeError('Private SAM ownership lost')
        forward = start([
            str(ROOT / 'hub/luadch-i2p-forward'),
            '--identity', str(DATA / 'cfg/i2p-hub.private'),
            '--sam-port', str(sam_port), '--target-port', '17650',
        ], capture=True)
        selector.register(forward.stdout, selectors.EVENT_READ)
        pending = b''
        status('Connecting')
        while not stopping:
            if any(child.poll() is not None for child in children):
                raise RuntimeError('Managed hub/router/SAM process exited; taking the service offline')
            for key, _ in selector.select(timeout=0.5):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    raise RuntimeError('SAM forwarder output closed')
                pending += chunk
                if len(pending) > 8192:
                    raise RuntimeError('Invalid forwarder status')
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    match = ADDRESS_LINE.fullmatch(line.decode('ascii', errors='replace').strip())
                    if match:
                        atomic_text(DATA / 'hub-address', 'adc://' + match[1] + '\n')
                        # SAM setup is not proof of a remotely reachable LeaseSet.
                        status('SAM active; I2P tunnels may still be building')
    except RuntimeError:
        # systemd signals the whole control group: child EOF/exit may race SIGTERM.
        if not stopping:
            raise
    finally:
        selector.close()
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
        deadline = time.monotonic() + 20
        for child in reversed(children):
            try:
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        state_file.unlink(missing_ok=True)
        print('Luadch-I2P: Offline', flush=True)


def main():
    parser = argparse.ArgumentParser(description='Manage the local I2P-only hub')
    parser.add_argument('command', choices=('run', 'status', 'info', 'start', 'stop', 'restart'))
    args = parser.parse_args()
    if args.command == 'run':
        run_service()
        return
    if os.geteuid() != 0:
        parser.error('Use sudo luadch-i2p ' + args.command)
    if args.command in ('start', 'stop', 'restart'):
        subprocess.run(['systemctl', args.command, 'luadch-i2p.service'], check=True)
        return
    state = RUN / 'status.json'
    print('I2P: ' + (json.loads(state.read_text())['state'] if state.exists() else 'Offline'))
    address = DATA / 'hub-address'
    print('Hub: ' + (address.read_text().strip() if address.exists() else 'Starting; check again in a few minutes'))
    if args.command == 'info':
        print((DATA / 'setup.txt').read_text(), end='')
        print('Keep these credentials private. Register members with +reg nick NAME 20 in the hub.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit('Luadch-I2P: ' + str(error))
