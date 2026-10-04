#!/usr/bin/python3
"""Initialize private persistent state once; never overwrite an existing identity."""
import os
from pathlib import Path
import pwd
import re
import secrets

ROOT = Path('/usr/lib/luadch-i2p')
DATA = Path('/var/lib/luadch-i2p')


def main():
    os.umask(0o077)
    account = pwd.getpwnam('luadch-i2p')
    for name in ('', 'cfg', 'log', 'certs', 'script-data', 'router'):
        directory = DATA / name
        if directory.is_symlink():
            raise SystemExit('Refusing a symlink in service state: ' + str(directory))
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(directory, account.pw_uid, account.pw_gid)
        directory.chmod(0o700)
    for source in (ROOT / 'defaults').iterdir():
        target = DATA / 'cfg' / source.name
        if not target.exists():
            with target.open('xb') as stream:
                stream.write(source.read_bytes())
            os.chown(target, account.pw_uid, account.pw_gid)
    users = DATA / 'cfg/user.tbl'
    if not users.exists():
        setup = DATA / 'setup.txt'
        # Recover an interrupted first initialization without rotating credentials.
        if setup.exists():
            text = setup.read_text()
            match = re.fullmatch(r'Administrator nickname: admin\nInitial password: ([A-Za-z0-9_-]{24})\n', text)
            if not match:
                raise SystemExit('Invalid existing setup credentials; refusing to overwrite')
            password = match[1]
        else:
            password = secrets.token_urlsafe(18)
            with setup.open('x') as stream:
                stream.write('Administrator nickname: admin\nInitial password: ' + password + '\n')
        with users.open('x') as stream:
            stream.write('return {{ badpassword=0, lastconnect=0, level=100, '
                         'nick="admin", password="' + password + '", rank="2" }}\n')
        os.chown(users, account.pw_uid, account.pw_gid)
    certificate = DATA / 'certs/ca-bundle.pem'
    if not certificate.exists():
        with certificate.open('xb') as stream:
            stream.write((ROOT / 'hub/lib/luadch/ca-bundle.pem').read_bytes())
        os.chown(certificate, account.pw_uid, account.pw_gid)
    lock = DATA / 'luadch.lock'
    if not lock.exists():
        with lock.open('x'):
            pass
        os.chown(lock, account.pw_uid, account.pw_gid)


if __name__ == '__main__':
    main()
