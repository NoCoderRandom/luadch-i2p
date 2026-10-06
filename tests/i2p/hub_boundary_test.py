#!/usr/bin/env python3
"""Exercise the installed I2P-only ADC hub with two local protocol clients."""

import base64
import contextlib
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "smoke"))
import tiger


class Frames:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def until(self, predicate, seconds=5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                text = line.decode("utf-8")
                if predicate(text):
                    return text
                continue
            self.sock.settimeout(max(0.01, deadline - time.monotonic()))
            data = self.sock.recv(8192)
            if not data:
                raise AssertionError("hub closed the connection while waiting for a frame")
            self.buffer += data
        raise AssertionError("timed out waiting for an ADC frame")


def send(sock, frame):
    sock.sendall((frame + "\n").encode("utf-8"))


def identity():
    pid = secrets.token_bytes(24)
    encode = lambda value: base64.b32encode(value).decode("ascii").rstrip("=")
    return encode(tiger.tiger(pid)), encode(pid)


def assert_private_inf(frame):
    fields = frame.split()
    assert not any(field.startswith(("I4", "I6", "U4", "U6")) for field in fields), frame
    su = next((field[2:] for field in fields if field.startswith("SU")), "")
    assert not any(token in su.split(",") for token in
                   ("TCP4", "TCP6", "UDP4", "UDP6", "NAT0", "SUDP", "CCPM")), frame


def handshake(sock, i2p=True, destination="A" * 516):
    frames = Frames(sock)
    # SAM STREAM FORWARD 3.1 sends the authenticated source before ADC bytes.
    send(sock, destination + "\nHSUP ADBASE ADTIGR" + (" ADIIPT" if i2p else ""))
    if not i2p:
        assert frames.until(lambda frame: frame.startswith("ISTA ")).startswith("ISTA 220")
        return frames, None
    assert "ADIIPT" in frames.until(lambda frame: frame.startswith("ISUP "))
    sid = frames.until(lambda frame: frame.startswith("ISID ")).split()[1]
    frames.until(lambda frame: frame.startswith("IINF "))
    return frames, sid


def login(sock, nick, destination):
    frames, sid = handshake(sock, destination=destination)
    cid, pid = identity()
    send(sock, f"BINF {sid} ID{cid} PD{pid} NI{nick} I2{destination} "
               "SUIIPT SL1 SS0 SF0 HN0 HR0 HO0")
    response = frames.until(lambda frame: frame.startswith((f"BINF {sid} ", "ISTA ")))
    assert response.startswith(f"BINF {sid} "), response
    assert f"I2{destination}" in response, response
    assert_private_inf(response)
    return frames, sid


def expect_rejected_binf(port, fields):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        frames, sid = handshake(sock)
        cid, pid = identity()
        send(sock, f"BINF {sid} ID{cid} PD{pid} NIRejectMe {fields} SL1 SS0")
        response = frames.until(lambda frame: frame.startswith("ISTA "))
        assert response.startswith("ISTA 240 "), response


def reserve_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def origin_admission(port):
    with contextlib.ExitStack() as stack:
        # Different I2P sources must not share the 16-connection loopback cap.
        for index in range(17):
            sock = stack.enter_context(socket.create_connection(("127.0.0.1", port), timeout=5))
            handshake(sock, destination=chr(ord("C") + index) * 516)
    print("SAM origin: 17 independent destinations admitted")

    def closed(sock):
        sock.settimeout(12)
        try:
            assert sock.recv(8192) == b"", "Rejected source received ADC data"
        except ConnectionResetError:
            pass

    with contextlib.ExitStack() as stack:
        for _ in range(16):
            sock = stack.enter_context(socket.create_connection(("127.0.0.1", port), timeout=5))
            handshake(sock, destination="V" * 516)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as extra:
            send(extra, "V" * 516 + "\nHSUP ADBASE ADTIGR ADIIPT")
            closed(extra)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as other:
            handshake(other, destination="W" * 516)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as released:
        handshake(released, destination="V" * 516)

    for header in ("HSUP ADBASE ADIIPT", "127.0.0.1", "::1", "X" * 16385):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            send(sock, header)
            closed(sock)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as split:
        split.sendall(b"Y" * 200)
        split.settimeout(0.1)
        try:
            split.recv(1)
            raise AssertionError("Partial SAM header created a hub user")
        except TimeoutError:
            pass
        send(split, "Y" * 316 + "\nHSUP ADBASE ADTIGR ADIIPT")
        assert "ADIIPT" in Frames(split).until(lambda frame: frame.startswith("ISUP "))
    with contextlib.ExitStack() as stack:
        for _ in range(64):
            sock = stack.enter_context(socket.create_connection(("127.0.0.1", port), timeout=5))
            sock.sendall(b"Z")
        with socket.create_connection(("127.0.0.1", port), timeout=5) as overflow:
            closed(overflow)
        closed(sock)  # Pending metadata has a fixed deadline, even with rate limits disabled.
    with socket.create_connection(("127.0.0.1", port), timeout=5) as recovered:
        handshake(recovered, destination="a" * 516)
    print("SAM origin: source cap/release, isolation, framing, pending cap/timeout passed")


def origin_auth_failures(port):
    source = "g" * 516
    for index in range(6):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            frames, sid = handshake(sock, destination=source)
            cid, pid = identity()
            send(sock, f"BINF {sid} ID{cid} PD{pid} NIOriginAuth{index} I2{source} SUIIPT SL1 SS0")
            frames.until(lambda frame: frame.startswith("IGPA "))
            send(sock, "HPAS " + "A" * 39)
            assert frames.until(lambda frame: frame.startswith("ISTA ")).startswith("ISTA 223 ")
    with socket.create_connection(("127.0.0.1", port), timeout=5) as blocked:
        send(blocked, source + "\nHSUP ADBASE ADTIGR ADIIPT")
        try:
            assert blocked.recv(8192) == b""
        except ConnectionResetError:
            pass
    with socket.create_connection(("127.0.0.1", port), timeout=5) as other:
        login(other, "Unaffected", "h" * 516)
    print("SAM origin: real failed-auth lockout affects only its source destination")


def run(install):
    with tempfile.TemporaryDirectory(prefix="luadch-i2p-boundary-") as root:
        staged = Path(root) / "luadch"
        shutil.copytree(install, staged)
        config = staged / "cfg" / "cfg.tbl"
        text = config.read_text(encoding="utf-8-sig")
        port = reserve_port()
        for pattern, replacement in (
            (r"(?m)^    tcp_ports = \{ 5000 \}", f"    tcp_ports = {{ {port} }}"),
            (r"(?m)^    reg_only = (?:true|false)", "    reg_only = false"),
            (r"(?m)^    etc_trafficmanager_activate = (?:true|false)", "    etc_trafficmanager_activate = false"),
            (r"(?m)^    log_events = false", "    log_events = true"),
        ):
            text, count = re.subn(pattern, replacement, text, count=1)
            assert count == 1, pattern
        assert re.search(r"(?m)^    i2p_only = true", text)
        config.write_text(text, encoding="utf-8")
        # Isolated disposable accounts, never copied from a lab/service profile.
        users = ["return {"]
        for index in range(6):
            users.append(f'{{ badpassword=0, lastconnect=0, level=10, nick="OriginAuth{index}", '
                         f'password="{secrets.token_hex(24)}", rank="2" }},')
        users.append("}")
        (staged / "cfg" / "user.tbl").write_text("\n".join(users), encoding="utf-8")

        logfile = staged / "log" / "i2p-boundary.log"
        with logfile.open("wb") as output:
            proc = subprocess.Popen([str(staged / "luadch")], cwd=root,
                                    stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                while True:
                    if proc.poll() is not None:
                        raise AssertionError(f"hub exited during startup: {proc.returncode}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AssertionError("hub did not bind its loopback ADC port")
                        time.sleep(0.1)

                origin_admission(port)
                origin_auth_failures(port)

                with socket.create_connection(("127.0.0.1", port), timeout=5) as stock:
                    handshake(stock, i2p=False)

                destination_a = "A" * 516
                destination_b = "B" * 516
                expect_rejected_binf(port, "SUIIPT")
                expect_rejected_binf(port, f"I2{destination_b} SUIIPT")
                expect_rejected_binf(port, f"I2{destination_a} SUIIPT I41.2.3.4")
                expect_rejected_binf(port, f"I2{destination_a} SUIIPT,TCP4")

                with contextlib.ExitStack() as stack:
                    alice = stack.enter_context(socket.create_connection(
                        ("127.0.0.1", port), timeout=5))
                    alice_frames, alice_sid = login(alice, "Alice", destination_a)
                    bob = stack.enter_context(socket.create_connection(
                        ("127.0.0.1", port), timeout=5))
                    bob_frames, bob_sid = login(bob, "Bob", destination_b)

                    bob_seen = alice_frames.until(
                        lambda frame: frame.startswith(f"BINF {bob_sid} "))
                    assert f"I2{destination_b}" in bob_seen, bob_seen
                    assert_private_inf(bob_seen)

                    send(alice, f"DCTM {alice_sid} {bob_sid} ADC/1.0 5000 token")
                    ctm = alice_frames.until(lambda frame: frame.startswith("ISTA "))
                    assert ctm.startswith("ISTA 144 ") and "FCCTM" in ctm, ctm

                    send(alice, f"DCTM {alice_sid} {bob_sid} I2P/1.0 0 token")
                    relayed_ctm = bob_frames.until(lambda frame: frame.startswith("DCTM "))
                    assert relayed_ctm == f"DCTM {alice_sid} {bob_sid} I2P/1.0 0 token", relayed_ctm

                    send(bob, f"DRCM {bob_sid} {alice_sid} I2P/1.0 reply")
                    relayed_rcm = alice_frames.until(lambda frame: frame.startswith("DRCM "))
                    assert relayed_rcm == f"DRCM {bob_sid} {alice_sid} I2P/1.0 reply", relayed_rcm

                    send(alice, f"BINF {alice_sid} I41.2.3.4")
                    update = alice_frames.until(lambda frame: frame.startswith("ISTA "))
                    assert update.startswith("ISTA 240 "), update

                print("I2P hub boundary: two clients, private INF, I2P peer relay, and clearnet rejects passed")
            except Exception:
                output.flush()
                for path in (logfile, staged / "log" / "event.log",
                             staged / "log" / "error.log"):
                    if path.exists():
                        print(f"--- {path.name} ---", file=sys.stderr)
                        print(path.read_text(errors="replace")[-4000:], file=sys.stderr)
                raise
            finally:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: hub_boundary_test.py <installed-luadch-directory>")
    run(Path(sys.argv[1]).resolve())
