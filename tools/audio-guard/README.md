# AudioGuard (optional operator tool)

Checks the filenames advertised in peer file lists over the existing AirDC-I2P
Linux client's SAM transport. It never downloads shared file contents. This is
moderation, not content inspection, a legality check, or an upload firewall.
Peer transfers do not pass through the hub. A renamed file, a selectively served
file list or a transfer before a scan may evade this policy. Unavailable,
incomplete, malformed or oversized lists are **unverified**, never certified
safe and never grounds for a filename-policy kick.

## Policy

Allowed audio extensions (case-insensitive): `aa aac aax aif aiff alac ape flac
m4a m4b mka mp3 oga ogg opus wav wave wma wv`.

Allowed companions: `txt nfo m3u m3u8 pls cue sfv opf lrc`. Playlists and text
are not executed or followed. These formats can still contain unsafe links or
private information. Images, video containers, archives, executables, general
ebooks and extensionless files are not allowed. Directory names are not checked
as file extensions.

## Components

- `guard.py`: Python standard-library daemon using `/usr/lib/airdc-i2p/runtime.py`
  from the installed I2P-only Linux package. Dedicated empty profile and private
  bundled router; owned loopback API only. No external router, SOCKS, DNS-based
  hub endpoint or clearnet transport is added.
- `scripts/etc_audio_guard.lua`: optional hub plugin, disabled unless a private
  `cfg/audio_guard.tbl` exists. A dedicated registered **level 20** account can
  request only the fixed audio-policy disconnect. It cannot supply commands or
  reasons to execute, change settings, register users or ban administrators.
  The hub checks the account's registered name and the target's exact SID and
  CID immediately before the kick. Virtual bots, self, and levels 50+ are
  protected. Six kicks per minute maximum, reconnect hint 300 seconds.

The bot defaults to audit-only. Enforcement requires both `--enforce` and
`enforce = true` in the hub policy. New sessions are checked in sequence;
successful scans repeat after 30 minutes, incomplete scans after 5 minutes.
One scan is limited to 250,000 items, 10,000 directories and one hour; a directory
waits up to four minutes for I2P. Close/reopen lists for each scan to avoid stale
cached results. No filenames or paths are printed to the daemon journal.

## Operator Setup

Install the existing `airdc-i2p` Linux package. Use a dedicated unprivileged OS
account and a directory mode 0700. Create a dedicated registered hub account at
level 20 with a randomly generated password, not the hub administrator password.

In a private mode-0600 `settings.json`, supply `hub_url` (a portless
`adc://<52-character base32 destination>.b32.i2p` URL), `nick` and `password`.
Never put live values in source control. Do not add shares to the bot's profile.

Install the Lua plugin with the other hub scripts and add it to the configured
script list. In the hub's private `cfg/audio_guard.tbl`:

```lua
return { bot_nick = "AudioGuard", enforce = false }
```

Run `python3 guard.py --config /private/path/settings.json` under a service
manager. Give it only its own state directory, no administrator credentials or
NAS mount, and a reasonable memory limit. Verify a synthetic allowed list and
a synthetic rejected list in audit mode before enabling both enforcement flags.
The kicked client receives a fixed explanation and a pointer to `+rules`.
Stopping the bot stops checks; disconnecting users does not cancel pre-existing
peer streams. Administrator/operator shares require human review.

## Targeted Tests

```sh
python3 -m unittest discover -s tools/audio-guard -p test_guard.py -v
lua5.4 tests/unit/etc_audio_guard_test.lua
```

The plugin tests cover authorization, stale-session protection, protected users,
audit mode, rate limits and the fixed reason. Python tests cover pagination,
case-insensitive extension policy, companions, recursive lists, malformed data,
timeouts, scan limits, fresh scans and filename-free control commands.
