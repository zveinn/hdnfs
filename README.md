# HDNFS

HDNFS is an encrypted filesystem container, written in Rust. A volume is a regular file or a Linux block device. The `hdnfs` command creates directories and files inside that volume and encrypts every byte it writes. You copy files in and out from the command line, or open the same volume in a full-screen terminal UI.

Inside the container the layout is a small filesystem of directories and 1 MiB blocks. Data is stored in stripes of 8 blocks plus 3 Reed-Solomon parity blocks, so a few damaged blocks can be rebuilt. The same volume can hold SSH private keys and host records. Connecting loads a key into memory, starts OpenSSH, and closes the volume before the session begins.

## Capabilities

- Initialize a file or a block device as a volume
- Change the volume password without rewriting the files
- Directories and files: put, get, list, stat, mkdir, delete, rename
- Put and get copy a file or a directory tree, and keep the source modification time
- Put creates missing parent directories
- Delete a file, an empty directory, or a directory tree
- Repair a file while reading it, or scan and repair the whole volume
- Health also overwrites free blocks, so leftover ciphertext from a crash is gone
- Back up the superblock and the allocated blocks, and restore that image
- Grow a volume without moving the files already in it
- Full-screen UI for disks and file volumes, browsing, copy, move, delete, grow, health, backup, and SSH
- Store SSH keys and hosts in the volume and connect with the system `ssh`
- Store passwords by tag, generate one, and copy it to the clipboard

## Security

The password comes from a terminal prompt. It is at least 12 characters, and `init` asks for it twice. Argon2id (256 MiB, 3 passes, one lane) turns that password and a random salt into a key-encryption key. That key wraps a random data key. Each file has its own key, wrapped by the data key. `passwd` asks for the current password, then a new one twice, and wraps that same data key again. The three superblock copies are rewritten. Files are not. A backup keeps the password it was taken with.

Every block is sealed with XChaCha20-Poly1305 and a fresh random nonce. The authentication tag binds the block to the volume, the file, and its place on disk. Three copies of the superblock are kept, and a copy that fails authentication is ignored. The header begins with the plaintext marker `HDNFS2`. A file copied in keeps the source modification time, and copying it out sets that time again. Rename and move keep the same file key and the same blocks.

Each stripe is 8 data blocks and 3 parity blocks. `get` and `health` rebuild up to three damaged blocks in a stripe and write them back. A stripe with four or more damaged blocks stays as it is, and `health` exits 1. Delete and replace drop the file key and overwrite the freed blocks with random bytes.

SSH private keys are files inside the volume. `connect` passes a key to `ssh` through a memory file and closes that file once authentication succeeds. `key create` generates an ed25519 key. `key add` stores an existing private-key file unchanged.

Passwords are files under `/.drive/passwords`. The list shows the tag and the length. Copy puts the password on the clipboard and does not print it.

## Commands

```
hdnfs ui
hdnfs <volume> init [--size SIZE] [--force]
hdnfs <volume> passwd
hdnfs <volume> wipe
hdnfs <volume> put <src> <dest-path>
hdnfs <volume> get <src-path> <dest>
hdnfs <volume> mv <src-path> <dest-path>
hdnfs <volume> health
hdnfs <volume> backup [dest]
hdnfs <backup> restore <dest>
hdnfs <volume> del [-r] <path>
hdnfs <volume> grow --size SIZE
hdnfs <volume> list [path]
hdnfs <volume> stat [path]
hdnfs <volume> mkdir <path>
hdnfs <volume> ssh key create <tag> [--comment TEXT]
hdnfs <volume> ssh key add <tag> <file>
hdnfs <volume> ssh key delete <tag>
hdnfs <volume> ssh key list
hdnfs <volume> ssh key info <tag>
hdnfs <volume> ssh password add <tag>
hdnfs <volume> ssh password generate <tag> [--length N] [--symbols | --no-symbols]
hdnfs <volume> ssh password list
hdnfs <volume> ssh password delete <tag>
hdnfs <volume> ssh password copy <tag>
hdnfs <volume> ssh host create <tag> --key <key-tag> --hostname <host> [--user USER] [--port N] [--timeout SECONDS] [--option LINE]
hdnfs <volume> ssh host update <tag> --key <key-tag> --hostname <host> [--user USER] [--port N] [--timeout SECONDS] [--option LINE]
hdnfs <volume> ssh host delete <tag>
hdnfs <volume> ssh host list
hdnfs <volume> ssh host info <tag>
hdnfs <volume> ssh connect <tag> [-- <ssh options>]
```

`ui` lists disks and HDNFS files in the current directory, unlocks an existing volume, or initializes one. On that list, `n` starts a new file volume with the same init form, `c` changes the password of the highlighted volume, and `w` overwrites that whole file or device with random data after the path is typed again. Inside a volume, `e` moves the entry under the cursor, `d` then `r` deletes a directory tree, `g` on a directory copies that tree out, and `+` grows the volume. `?` lists the keys. The commands above stay available from the shell.

`init` creates a volume. A file requires `--size`. A block device uses the whole device unless `--size` is set, and it requires `--force`. `SIZE` is bytes, with an optional suffix `K`, `M`, `G`, or `T`. If the device node is not writable, `hdnfs` asks for a sudo password and grants your user read-write on that node. The volume password is a separate prompt.

`put` copies a host file or directory into the volume and creates missing directories. The name in the volume is the destination path, not the host name. A directory is copied as a tree. The source modification time is stored, and `get` sets it again on the way out. `get` copies a volume file or directory and writes rebuilt blocks back first. `mv` renames or moves inside the volume. When the destination is a directory, the source is moved into it under its own name. The file key and the blocks stay where they are. `del` removes a file or an empty directory. `del -r` removes a directory tree, drops every file key in it, and overwrites the freed blocks. `health` checks every block, rewrites what it can rebuild, overwrites free blocks with random data, and exits 1 when a stripe is beyond repair. `backup` stores the superblock and the allocated blocks. Free blocks are left out. Pass the destination, or omit it and type the path when asked. `restore` writes that image and fills the free blocks with random data. An older byte-for-byte image still restores. `grow --size` makes a file volume longer, or uses more of a block device, when the new size still fits the allocation bitmap. Existing files are not moved. `wipe` overwrites every byte of the file or block device with random data and leaves the length unchanged. It asks for the path to be typed again and does not ask for the volume password. A symlink is refused. Stopping the write leaves the bytes already written random. `list` and `stat` take an optional path. `mkdir` creates one directory.

`ssh key`, `ssh host`, and `ssh password` manage records stored in the volume. `ssh connect` closes the volume, then runs `ssh`. Anything after `--` is passed through to `ssh`.
