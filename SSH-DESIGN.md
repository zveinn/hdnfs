# SSH keys and hosts

SSH private keys and host records live in the unlocked volume. The volume password is the only password. `connect` loads one private key into an anonymous memory file, points `ssh -i` at it, and closes that file as soon as authentication succeeds.

The files browser lists `/ssh` like any other directory. `get`, `put`, and `del` can read and write those files. The `ssh` commands below are the supported way to manage them.

## Layout

```
/ssh/keys/<tag>/meta
/ssh/keys/<tag>/private
/ssh/hosts/<tag>
```

A tag is the directory or file name. It is case-sensitive, 1 to 64 bytes, and matches `[A-Za-z0-9][A-Za-z0-9._-]*`. The volume's normal path rules still apply.

`private` is written first, then `meta`. `list` and `info` read `meta` only. `connect` is what reads `private`.

## Key record

`meta` is UTF-8 JSON:

```json
{
  "version": 1,
  "public": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGm7... hdnfs:laptop"
}
```

`version` is `1`. Unknown fields are rejected. `public` is optional. When the stored file parses, it is one OpenSSH public-key line, at most 16 KiB, with no newline. The algorithm, fingerprint, and comment come from that line. When the file does not parse, the field is omitted.

`private` is the file that was stored, unchanged, at most 256 KiB. `key create` writes OpenSSH private-key text. `key add` copies whatever file it was given.

`key create` generates an ed25519 key in memory. It has no key passphrase. The comment defaults to `hdnfs:<tag>`. `--comment` replaces it and is 1 to 128 bytes with no control characters.

`key add` copies the file byte for byte and does not require it to parse. An empty file is refused. The size cap is 256 KiB. When the bytes are an OpenSSH private key this program can read, `meta` records the public line. Otherwise the private bytes are still stored, and `connect` passes them to `ssh -i`. `ssh` accepts key types this program does not parse, including a key that already has a passphrase. `ssh` asks for that passphrase itself. The copy on the host disk is only the file the user passed in.

`key delete` refuses while any host's `key` field is that tag. A host file that cannot be read also blocks the delete. The tag must be typed again before the password prompt. The private file, the meta file, and the tag directory are removed. `/ssh` and `/ssh/keys` stay.

`key list` prints the tag, algorithm, fingerprint, and comment. A tag whose `meta` is missing prints `incomplete`. A tag whose `meta` has no public line prints the tag alone. A tag whose `meta` cannot be read prints `invalid`.

`key info` prints the tag, algorithm, fingerprint, comment, created and modified times, and the public-key line. Without a public line it prints the tag and the two times.

## Host record

`/ssh/hosts/<tag>` is UTF-8 JSON:

```json
{
  "version": 1,
  "key": "laptop",
  "hostname": "203.0.113.10",
  "user": "root",
  "port": 22,
  "options": [
    "ProxyJump bastion",
    "LocalForward 8080 localhost:8080",
    "ServerAliveInterval 30"
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `version` | yes | `1` |
| `key` | yes | Tag of a key under `/ssh/keys` |
| `hostname` | yes | DNS name or IP, 1 to 255 bytes. No `@`, `/`, or whitespace. Colons are allowed for IPv6 |
| `user` | no | Remote user, 1 to 64 bytes, no `@` or whitespace. Omitted means the local user |
| `port` | no | `1`–`65535`. Omitted means OpenSSH's default |
| `timeout` | no | `ConnectTimeout`, `1`–`3600` seconds. Omitted means OpenSSH's default |
| `options` | no | OpenSSH keyword lines, at most 64, each at most 1024 bytes |

`user`, `port`, and `options` are omitted from the file when empty. Unknown fields are rejected. The key tag must already exist.

Each option line is one keyword and its value. The keyword is ASCII letters. These keywords are rejected, in any case: `Host`, `Match`, `Include`, `IdentityFile`, `IdentitiesOnly`, `IdentityAgent`, `CertificateFile`, `PKCS11Provider`, `LocalCommand`, `PermitLocalCommand`, `ConnectTimeout`. `ConnectTimeout` is the `timeout` field.

`host create` fails if the tag exists. `host update` fails if it does not. Update rewrites the record. A user, port, or option that is left off the command is cleared. Repeating `--option` sets the whole list. `host delete` removes that file and leaves the key in place. The tag is typed again before the password prompt.

`host list` prints the tag, the target, and the key tag. The target is `user@hostname` when a user is set, plus `:<port>` when a port is set.

`host info` prints the fields and the rendered SSH config.

`ProxyJump` is an OpenSSH destination, not another host tag.

## Connect

The rendered config exists only in a second memory file:

```
Host hdnfs
  HostName 203.0.113.10
  User root
  Port 22
  ConnectTimeout 15
  ProxyJump bastion
  LocalForward 8080 localhost:8080
  ServerAliveInterval 30
```

Structured fields are written first, so an option line cannot replace the hostname, user, port, or connect timeout.

```
ssh -o IdentitiesOnly=yes \
    -i /proc/<pid>/fd/<key> \
    -o PermitLocalCommand=yes \
    -o LocalCommand='kill -USR1 <pid> && cat /proc/<pid>/fd/<ready> >/dev/null' \
    -F /proc/<pid>/fd/<config> \
    <extra options> \
    hdnfs
```

`SSH_AUTH_SOCK` is unset. Extra arguments are SSH options placed before the destination, which is how `-L` works. An extra `-i`, or an option that sets a forbidden keyword, is rejected. The destination word is always `hdnfs`. Host-key checking still uses the normal `known_hosts` file. Nothing is written under `~/.ssh`.

The private-key bytes are wiped after they are written to the memory file. Both memory files are mode `0600`, created with `memfd_create` and `MFD_CLOEXEC`, and are not on a filesystem. `LocalCommand` runs only after authentication and closes the key file. If authentication never succeeds, the key file is closed when `ssh` exits. Core dumps are disabled before the private key is read. `ssh` still holds the parsed key in its own memory after that.

`ssh` runs in its own process group. The TUI keeps that group in the background and shows a connecting screen until authentication succeeds, or until `ssh` stops to read the terminal. Esc, `q`, or Ctrl-C on that screen cancels the attempt. A host-key prompt is given the terminal immediately. If that attempt fails before authentication, the TUI comes back and shows `ssh`'s error text.

Once authentication succeeds, the key file is already closed. `ssh` is still inside `LocalCommand` and has not requested the remote pty yet. The TUI leaves the alternate screen, restores the terminal mode it saved at startup, and only then lets `LocalCommand` finish. `ssh` copies that mode to the remote pty, so the login text, echo, and line breaks are the normal ones. The TUI then drops the volume lock and replaces its own process image with a waiter of the same process id. The shell is still waiting on that process, so it does not take the terminal back, and `ssh` keeps the session. The waiter is not the TUI: the volume key is gone with the old image. When `ssh` exits, the waiter restores the startup terminal mode again and exits with `ssh`'s status. It does not return to the host list. Ctrl-Z stops `ssh` and then the waiter, so the shell gets its prompt; continuing the job continues `ssh`. The CLI does not hold `LocalCommand`; its terminal was never put into raw mode.

The CLI reads the key, closes the volume, then starts `ssh` in the foreground, and exits with `ssh`'s status. It prints `ssh`'s error text when the session fails.

## Commands

Commands are case-insensitive. The volume password is asked once, as for `get`. A delete asks for the tag before that password. A confirmation that does not match deletes nothing and does not ask for the password.

```
hdnfs <volume> ssh key create <tag> [--comment TEXT]
hdnfs <volume> ssh key add <tag> <file>
hdnfs <volume> ssh key delete <tag>
hdnfs <volume> ssh key list
hdnfs <volume> ssh key info <tag>

hdnfs <volume> ssh host create <tag> --key <key-tag> --hostname <host> [--user USER] [--port N] [--timeout SECONDS] [--option LINE]...
hdnfs <volume> ssh host update <tag> --key <key-tag> --hostname <host> [--user USER] [--port N] [--timeout SECONDS] [--option LINE]...
hdnfs <volume> ssh host delete <tag>
hdnfs <volume> ssh host list
hdnfs <volume> ssh host info <tag>

hdnfs <volume> ssh connect <tag> [-- <ssh options>]
```

## TUI

The top bar shows `menu` after a volume is open, except while the put or get screen is up. The current section is named beside it. `m` opens a dropdown of `files`, `hosts`, and `keys`. `j`, `k`, Up, and Down move in that list. Enter opens the highlighted section. Esc or `m` closes the dropdown and stays where you were. A held `m` does not open or close it again. While a path, password, find field, or other text field is open, `m` is typed.

`files` is the current browser, and its list includes `/ssh`.

`hosts` lists host tags. `j` and `k` move. Enter connects. `i` shows the record. `n` asks for the tag, key tag, hostname, user, port, timeout, and option lines. An empty user, port, or timeout is left unset. An empty option line finishes the host. `e` edits the selected host and starts from its saved key, hostname, user, port, timeout, and options. On the option step, `-` drops the last option. `d` asks for the tag to be typed again. Esc returns to the disk list. `q` quits.

On the key list, Enter and `i` show the public key. `n` creates a key. `a` adds a host file. `d` deletes after the tag is typed again. The key list is the `keys` item in the menu.

A failed action is shown on a page that closes on the next key. Connect keeps the host list up and shows a bar above the hotkeys until `ssh` authenticates: one spinning character, the elapsed time, and the host. Esc, `q`, and Ctrl-C cancel it and stay on the host list. A host-key prompt takes the terminal immediately. Rejecting it returns to that list and shows the error. After authentication the TUI closes the key, drops the volume, and exits into the session. When `ssh` exits, the shell prompt comes back. A failed session prints `ssh`'s own error text, including a line that starts with `ssh:` when the status is zero. A clean session stays quiet.
