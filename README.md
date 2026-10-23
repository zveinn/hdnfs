# HDNFS

HDNFS is an encrypted filesystem container, written in Rust. A volume is a regular file or a Linux block device. The `hdnfs` command creates directories and files inside that volume and encrypts every byte it writes. You copy files in and out from the command line, or open the same volume in a full-screen terminal UI.

Inside the container the layout is a small filesystem of directories and 1 MiB blocks. Data is stored in stripes of 8 blocks plus 3 Reed-Solomon parity blocks, so a few damaged blocks can be rebuilt. The same volume can hold SSH private keys and host records. Connecting loads a key into memory, starts OpenSSH, and closes the volume before the session begins.

## Capabilities

- Initialize a file or a block device as a volume
- Directories and files: put, get, list, stat, mkdir, delete
- Put creates missing parent directories
- Repair a file while reading it, or scan and repair the whole volume
- Full-screen UI for disks, browsing, copy, delete, health, and SSH
- Store SSH keys and hosts in the volume and connect with the system `ssh`

## Security

The password comes from a terminal prompt. It is at least 12 characters, and `init` asks for it twice. Argon2id (256 MiB, 3 passes, one lane) turns that password and a random salt into a key-encryption key. That key wraps a random data key. Each file has its own key, wrapped by the data key.

Every block is sealed with XChaCha20-Poly1305 and a fresh random nonce. The authentication tag binds the block to the volume, the file, and its place on disk. Three copies of the superblock are kept, and a copy that fails authentication is ignored. The header begins with the plaintext marker `HDNFS2`.

Each stripe is 8 data blocks and 3 parity blocks. `get` and `health` rebuild up to three damaged blocks in a stripe and write them back. A stripe with four or more damaged blocks stays as it is, and `health` exits 1. Delete and replace drop the file key and overwrite the freed blocks with random bytes.

SSH private keys are files inside the volume. `connect` passes a key to `ssh` through a memory file and closes that file once authentication succeeds. `key create` generates an ed25519 key. `key add` stores an existing private-key file unchanged.

## Commands

```
hdnfs ui
hdnfs <volume> init [--size SIZE] [--force]
hdnfs <volume> put <src> <dest-path>
hdnfs <volume> get <src-path> <dest>
hdnfs <volume> health
hdnfs <volume> del <path>
hdnfs <volume> list [path]
hdnfs <volume> stat [path]
hdnfs <volume> mkdir <path>
hdnfs <volume> ssh key create <tag> [--comment TEXT]
hdnfs <volume> ssh key add <tag> <file>
hdnfs <volume> ssh key delete <tag>
hdnfs <volume> ssh key list
hdnfs <volume> ssh key info <tag>
hdnfs <volume> ssh host create <tag> --key <key-tag> --hostname <host> [--user USER] [--port N] [--timeout SECONDS] [--option LINE]
hdnfs <volume> ssh host update <tag> --key <key-tag> --hostname <host> [--user USER] [--port N] [--timeout SECONDS] [--option LINE]
hdnfs <volume> ssh host delete <tag>
hdnfs <volume> ssh host list
hdnfs <volume> ssh host info <tag>
hdnfs <volume> ssh connect <tag> [-- <ssh options>]
```

`ui` lists disks, unlocks an existing volume, or initializes one. The commands above stay available from the shell.

`init` creates a volume. A file requires `--size`. A block device uses the whole device unless `--size` is set, and it requires `--force`. `SIZE` is bytes, with an optional suffix `K`, `M`, `G`, or `T`. If the device node is not writable, `hdnfs` asks for a sudo password and grants your user read-write on that node. The volume password is a separate prompt.

`put` copies a host file into the volume and creates missing directories. `get` copies a volume file out and writes rebuilt blocks back first. `health` checks every block, rewrites what it can rebuild, and exits 1 when a stripe is beyond repair. `list` and `stat` take an optional path. `del` removes a file or an empty directory. `mkdir` creates one directory.

`ssh key` and `ssh host` manage records stored in the volume. `ssh connect` closes the volume, then runs `ssh`. Anything after `--` is passed through to `ssh`.
