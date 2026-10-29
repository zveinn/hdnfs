# HDNFS v2

HDNFS v2 is an encrypted filesystem container. A volume is a regular file or a Linux block device. The `hdnfs` command creates directories and files inside that volume, encrypts every byte it writes, and reads them back. It does not mount the volume into the kernel.

v1 (Go, on `main`) is a flat table of 1000 slots of 50 KB. v2 does not reuse that layout. A volume written by one version cannot be read by the other.

## Threat model

The attacker has a copy of the volume and can read or modify any byte while the command is not running. The password is not known to the attacker.

The design stops these attacks:

- Guessing a normal password offline. The password is stretched with Argon2id and a unique 32-byte salt.
- Reading file contents, names, or directory structure. They live only inside authenticated ciphertext.
- Flipping, truncating, reordering, or moving ciphertext. Every block is sealed with XChaCha20-Poly1305 and additional data that names the volume, the inode, the logical index, and the physical block.
- Reusing a nonce. Each seal uses a fresh 192-bit random nonce. File contents use a per-file key, so blocks from two files are sealed under different keys.
- Rolling the superblock back to a torn write. Three superblock copies are kept. The copy with the higher generation wins, and a copy that fails authentication is ignored.
- Losing a file because one, two, or three blocks in a stripe fail. Each stripe is 8 data blocks and 3 parity blocks. Any 8 of those 11 rebuild the data, and `get` and `health` write the rebuild back.
- Deleting a file and leaving its ciphertext readable to someone who later learns the password. `del` and replace drop the file key and overwrite the freed blocks with random bytes.

The design does not stop these attacks:

- A password that is long enough but easy to guess (`password1234` is rejected; a clever weak password is not).
- Malware on the machine while a command is running. The data key is in process memory.
- Restoring an older full-disk image over the volume. That image is a previous valid state. No local cipher can tell it from the real disk.
- Four or more failed blocks in the same stripe. Those bytes cannot be rebuilt. `health` counts them and leaves them in place.
- A stolen machine that is unlocked, or a person who can read the terminal.
- Hiding that the disk is an HDNFS volume. The superblock starts with the plaintext magic `HDNFS2`. This is encryption, not steganography.

Post-quantum key encapsulation and signatures are not used. This volume has one secret, the password. ML-KEM and ML-DSA do not add confidentiality on top of a password-derived 256-bit key. AES-256 and ChaCha20 already meet the usual post-quantum bar for symmetric encryption: Grover’s algorithm leaves about 128 bits of work. The construction below uses ChaCha20 under a 256-bit key and never uses elliptic curves.

## Keys

```
password + salt --Argon2id--> key-encryption key (32 bytes)
random 32 bytes             --> data key, wrapped by the key-encryption key
random 32 bytes per inode   --> file key, wrapped by the data key
```

Argon2id parameters are stored in the superblock so a later volume can raise them. The CLI always uses the default. The library accepts other parameters so tests can run without allocating 256 MiB.

| Parameter | CLI default |
|---|---|
| Type | Argon2id, version 0x13 |
| Memory | 256 MiB (262144 KiB) |
| Iterations | 3 |
| Parallelism | 1 |
| Output | 32 bytes |
| Salt | 32 bytes from the OS CSPRNG, stored in the clear |

The data key is created at `init` and wrapped once. `passwd` rewraps that key with a new salt and nonce and rewrites all three superblock copies at the same generation. File bytes are not rewritten. A backup keeps the password it was taken with. A crash between copies leaves both passwords able to open a consistent volume, and the next commit rewrites every copy from the wrap held in memory.

Open refuses Argon2 parameters above 512 MiB, 8 iterations, or 8 lanes. A crafted header cannot force an unbounded allocation. The CLI default fits inside that cap.

Each inode has its own file key. Directory blocks and file blocks are sealed with that key. The inode record itself is sealed with the data key, because the inode is what stores the wrapped file key. Sealing an inode with the file key would be circular.

On `del` and on replace, the old inode id is abandoned and the old file key is destroyed with the inode block. New contents of a replaced file are written under a new inode id and a new file key. Created time is kept. `put` sets the modified time from the source file. `write_bytes` sets it to the current time. `mv` does not rewrite the inode, so both times stay. `get` sets the host file's modification time from the inode.

The data key is locked with `mlock` when the OS allows it. Failure to lock is not fatal. Keys and password bytes are wiped with `zeroize` when they are dropped. The password is never taken from the environment or from argv.

### Password rules

- At least 12 Unicode scalar values and at least 12 bytes.
- At most 1024 bytes.
- No NUL byte.
- Not equal, ignoring case, to a small built-in deny list of common passwords (`password1234`, `123456789012`, `qwerty123456`, and similar).

`init` asks for the password twice. `passwd` asks for the current password, then the new password twice. Every other command asks once. The prompt is printed to stderr and the terminal does not echo.

### Nonces and additional data

XChaCha20-Poly1305, 32-byte key, 24-byte nonce, 16-byte tag. A new random nonce is used for every seal. An all-zero nonce is discarded and drawn again.

File, directory, inode, and bitmap blocks all carry the same additional-data layout (48 bytes, little-endian):

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | volume id |
| 16 | 1 | purpose |
| 17 | 3 | zero |
| 20 | 8 | inode id (0 for a bitmap block) |
| 28 | 8 | logical index |
| 36 | 8 | physical block index |
| 44 | 4 | extra (bitmap slot, otherwise 0) |

Purpose values: `1` file contents, `2` directory contents, `3` inode record, `4` allocation bitmap, `5` parity.

`extra` is the bitmap slot for a bitmap block, the parity index `0`, `1`, or `2` for a parity block, and `0` otherwise. The logical index of a parity block is the stripe number. Parity of file or directory contents is sealed with that inode's file key. Parity of an inode chain or of the bitmap is sealed with the data key.

The data-key wrap uses additional data `volume id || "dek-v1"`. A file-key wrap uses `volume id || inode id || "file-key-v1"`. The superblock body uses `volume id || "sb-body-v1"`.

Binding the physical block index means a ciphertext copied to a different block does not decrypt. The directory entry has to point at the block that was sealed.

## On-disk layout

Capacity starts fixed when the volume is created. `grow` can raise it while the bitmap slot stays the same size. A file volume takes `--size`. A block device uses its size (`BLKGETSIZE64`) unless `--size` is also given. That size must be no larger than the device. Initialization then writes only that prefix, starting at byte 0, and leaves the rest of the device untouched. Bytes past the last full block inside the chosen span are filled with random data and then ignored.

```
offset 0          superblock copy 0          4096 bytes
offset 4096       superblock copy 1          4096 bytes
offset 8192       superblock copy 2          4096 bytes
offset 12288      physical block 0           1 MiB
                  physical block 1           1 MiB
                  ...
```

`BLOCK_SIZE` is 1_048_576. Each block is one frame:

```
0 .. 24                         random nonce
24 .. BLOCK_SIZE                ciphertext and 16-byte tag
```

The plaintext inside a frame is always `PAYLOAD = BLOCK_SIZE - 24 - 16` bytes (1_048_536). Short records are zero-padded inside the plaintext, before encryption, so every block on disk is the same size and the padding is not visible.

Physical blocks are split:

```
0 .. span-1           bitmap slot 0
span .. 2*span-1      bitmap slot 1
2*span .. end         allocatable data blocks
```

`B` is the smallest positive integer such that `B` blocks can store one bit per allocatable data block. Each bitmap slot is those `B` blocks plus `ceil(B / 8) * 3` parity blocks, and `span` is that sum. `data_block_count = total_physical_blocks - 2*span`. Init refuses a volume with fewer than 8 allocatable data blocks. With one bitmap block, `span` is 4, so the smallest volume is 16 physical blocks plus the 12 KiB of superblocks, which is 16_789_504 bytes. Real volumes should be much larger: replacing a file needs a second copy of that file free at the same time, and parity spends three blocks for every eight (see crash safety).

The bitmap covers only allocatable blocks. Bit `i` corresponds to physical block `2*span + i`. Bit value 1 means used. The bit index is little-endian inside each byte (bit 0 is the least significant bit). Unused bits in the last byte are zero. Init marks four blocks used: the root inode's chain block and its three parity blocks. The empty root has no content blocks.

### Why this is not two bump pointers

Metadata does not grow forward from byte 0, and file bytes do not grow backward from the last byte. That scheme is a pair of bump allocators. It works until a delete punches a hole. After that, "full" is a free-space question, not a collision of two pointers, and a crash can step one pointer into live data.

Blocks plus a bitmap answer the same fullness question: the volume is full when an operation cannot reserve the data blocks it needs. Free blocks and sealed blocks are indistinguishable after init, because free blocks are random and sealed blocks are ciphertext.

### Superblock

A superblock is 4096 bytes. The prefix is plaintext because the password stretch cannot start without it. The body is sealed with the data key.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `HDNFS2\0\0` |
| 8 | 2 | version `1` (u16) |
| 10 | 2 | header length `256` (u16) |
| 12 | 4 | Argon2 memory, KiB (u32) |
| 16 | 4 | Argon2 iterations (u32) |
| 20 | 4 | Argon2 parallelism (u32) |
| 24 | 32 | salt |
| 56 | 16 | volume id |
| 72 | 24 | nonce of the wrapped data key |
| 96 | 48 | wrapped data key (32-byte key plus tag) |
| 144 | 24 | nonce of the sealed body |
| 168 | 2 | body ciphertext length, including tag: `144` |
| 170 | 86 | zero |
| 256 | 144 | sealed body |
| 400 | 3696 | zero |

All integers are little-endian.

The body plaintext is 128 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | generation (u64), starts at 1 |
| 8 | 8 | total physical blocks |
| 16 | 8 | allocatable start (`2*span`) |
| 24 | 8 | data block count |
| 32 | 8 | used block count |
| 40 | 8 | next inode id |
| 48 | 8 | root inode id (`1`) |
| 56 | 8 | root inode physical block |
| 64 | 8 | created time, unix seconds (i64) |
| 72 | 4 | active bitmap slot, 0 or 1 |
| 76 | 4 | bitmap blocks per slot (`B`) |
| 80 | 8 | flags, must be 0 |
| 88 | 8 | root chain parity block 0 |
| 96 | 8 | root chain parity block 1 |
| 104 | 8 | root chain parity block 2 |
| 112 | 16 | zero |

The three root parity addresses are inside the allocatable range, distinct, and distinct from the root block.

Open reads all three copies, derives the key-encryption key once when the salts match, and keeps the copy that authenticates and has the higher generation. Equal generations prefer the lower index. A copy with a bad magic is skipped. If every copy with a valid magic fails the data-key wrap, the password is wrong or the header is corrupt. If the wrap succeeds and every body fails, the volume is corrupt.

A commit writes `generation + 1` into one copy that is not the active copy and syncs. That sync is the commit. It then writes the same generation into the other two copies and syncs again. A crash before the first of those writes keeps the old generation. A crash after it, and before the mirrors, leaves one new copy and two old ones. The new copy wins.

### Inode record

Inode id 0 is never used. The root directory is inode 1. The next id starts at 2.

An inode record is sealed with the data key, purpose `3`, and may span blocks. Each block's plaintext starts with a 12-byte chain header and is then zero-padded to `PAYLOAD`:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | next physical block, or `u64::MAX` on the last block |
| 8 | 4 | number of record bytes stored in this block |
| 12 | … | record bytes |

The concatenated record is:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `INOD` |
| 4 | 2 | version `2` |
| 6 | 1 | kind: `1` directory, `2` file |
| 7 | 1 | flags, 0 |
| 8 | 8 | inode id |
| 16 | 8 | created, unix seconds |
| 24 | 8 | modified, unix seconds |
| 32 | 8 | logical size |
| 40 | 24 | file-key wrap nonce |
| 64 | 48 | wrapped file key |
| 112 | 4 | content block count |
| 116 | 8 each | physical block index of each content block, in order |
|  | 4 | content parity block count |
|  | 8 each | physical block index of each content parity block, in order |

Version 1 is rejected. `size` matches the content block count, not the parity blocks. An empty object has no content blocks and no content parity. Every stored inode has at least one chain block, so it has at least three chain-parity addresses.

The caller knows the inode id before decryption. The root id comes from the superblock. Any other id comes from the parent directory entry. The id inside the record must match. That is what lets the additional data include the inode id.

### Directory and file contents

Content blocks are sealed with the inode's file key. Directories use purpose `2`. Files use purpose `1`. The logical index is the content-block number, starting at 0.

A directory's logical bytes are the concatenation of its entries, and `size` is that length. An empty directory has size 0 and no content blocks. A directory is loaded into memory. A directory larger than 32 MiB is rejected.

A directory entry:

| Size | Field |
|---|---|
| 2 | name length in bytes |
| name length | name, UTF-8 |
| 8 | child inode id |
| 1 | child kind |
| 8 | child inode physical block |
| 8 | child logical size (0 for a directory) |
| 2 | chain parity count |
| 8 each | chain parity physical blocks |

The parity count is nonzero, a multiple of 3, and at most 4096. The root directory is not a directory entry. Its three chain-parity addresses live in the superblock.

Entries are sorted by raw name bytes, strictly increasing. Lookup is a binary search. `list` prints that order and does not decrypt file bodies.

A file is streamed in `PAYLOAD`-sized chunks. The last chunk is zero-padded inside the plaintext. `size` is the real byte count. Empty files have no content blocks. A file may be as large as the free space allows, which includes files of 10 GiB on a volume that has room for them.

### Bitrot

Content, inode chains, and bitmap slots use the same Reed-Solomon code: GF(2^8), a Cauchy matrix, 8 data shards, and 3 parity shards. A short stripe is padded with known zeros that are not stored. Any 8 of the 11 symbols rebuild the data, so a one-block stripe can be rebuilt from any single survivor. Four failed members of one stripe cannot be rebuilt.

New blocks in a stripe are placed at least 64 blocks apart when the volume has room. A smaller volume takes any free block. A write does not fail because the gap is unavailable. Blocks freed in the same transaction are not reused.

Free space is not parity-protected. Free blocks stay random, and blocks freed by `del` or replace are overwritten with random bytes after the commit. Usable payload is about 8/11 of the allocatable blocks, and directories and inode records spend blocks on parity as well.

A read checks the tag of every member. When every member authenticates, the parity is recomputed and compared, and a mismatch is corruption. When some members fail and at least 8 authenticated symbols remain, counting the known zero pad, the data is rebuilt in memory. A failed parity tag is not treated as a symbol when the data blocks already authenticate. `list` and `stat` do not write the rebuild back. `get` does, before it renames the destination into place. If that write fails, the previous destination stays. A shared lock that finds damage returns an error and does not rename. The CLI `get` takes the exclusive lock so it can repair.

A bitmap data block that fails at open is rebuilt from that slot's parity. If the rebuild fails, open fails. Damage that is only in bitmap parity is left for `health`. The next exclusive commit rewrites the inactive bitmap slot.

`health` holds the exclusive lock and walks the bitmap, every inode chain, and every content stripe. Each repaired object is its own transaction, so earlier repairs stay if a later one fails or the scan is canceled. A clean volume does not get a new generation. After the walk it overwrites every free data block with random bytes. That scrub does not bump the generation, and a cancel during the walk skips it. The report is checked blocks, repaired blocks, unrepairable objects, and scrubbed blocks.

An inode chain longer than one block stores only the first block's address in the directory entry, plus the parity addresses. A later chain block that fails authentication cannot be rebuilt. A file of about 10 GiB fits in one chain block, and that block plus its three parity blocks can be rebuilt from any one survivor. A second chain block is on the order of 90 GiB of content.

## Crash safety

One process holds an exclusive `flock` for `init`, `put`, `mkdir`, `del`, `get`, and `health`. `list` and `stat` hold a shared lock. The superblock and bitmap are read after the lock is taken.

Mutations are copy-on-write:

1. Allocate new blocks and write their ciphertext. A block freed in this transaction is not allocated again until the next transaction.
2. `fsync`.
3. Write the inactive bitmap slot and `fsync`. The new bitmap marks the new blocks used and the old blocks free, including the blocks of the bitmap slot itself being reserved rather than allocatable.
4. Write one superblock copy that is not the active copy, with `generation + 1`, and `fsync`. This is the commit.
5. Write that same generation into the other two copies and `fsync`.
6. Overwrite every freed data block with random bytes and `fsync`.

A crash before step 4 leaves the previous generation in place. Blocks written for the failed transaction are not referenced. The next allocation overwrites them. A crash after step 4 and before step 5 leaves one new copy and two old ones, and the new copy wins. A crash during step 6 leaves free blocks that still contain old ciphertext until something allocates or scrubs them. `del` reports a scrub failure if step 6 fails after the superblock is durable. It does not roll the superblock back.

Replacing a file, and rewriting a directory, needs free space for the new blocks while the old blocks are still reserved. A nearly full volume can refuse a replace that would fit after the old blocks were reusable. The error is "not enough free space".

`put` creates missing parent directories as their own transactions. If the file write then fails, those directories stay. The file is published only when its last byte and the updated directory entry are in the committed superblock. A failed replace leaves the previous file in place.

## Paths

Paths are absolute inside the volume and start with `/`. The only path that is only `/` is the root.

- No empty components (`//`), no trailing slash, no `.`, no `..`.
- A component is 1 to 255 bytes of UTF-8.
- The whole path string is at most 4096 bytes.
- `/` and NUL cannot appear in a name. Bytes below 0x20, and 0x7F, are rejected.
- Comparison is raw bytes. Names are case-sensitive and are not Unicode-normalized.

The type of an existing name is fixed.

- `put` onto a directory is refused. A directory is not turned into a file.
- `mkdir`, or an intermediate component of `put`, onto a file is refused. A file is not turned into a directory.
- The same name can be reused as the other type only after `del` removes it.
- `put` of a file onto an existing file replaces that file. `put` of a directory creates that directory when it is missing and copies the children into it. An existing directory is reused. A symlink is refused. `get` of a directory writes that tree to the destination. `mv` moves a directory entry to another name. The inode id, file key, content blocks, and timestamps stay. The destination parent must already exist. When the destination path is an existing directory, the source is moved inside it under its own name. A file moved onto a file replaces that file. A directory is not moved onto a file, and a directory is not moved into itself. `del -r` frees every inode in the tree in one transaction. `del` without `-r` still refuses a directory that has entries.
- `mkdir` onto an existing directory fails.

`put /path1/path2/path3/file` creates `/path1`, `/path1/path2`, and `/path1/path2/path3` when they are missing, then writes the file. The name stored in the volume is the last component. The host filename is not used. `mkdir` creates only the last component; the parent must already exist.

`del /` is refused. `del` of a file removes it. `del` of an empty directory removes it. `del` of a directory that still has entries fails.

There are no users, permissions, symlinks, or hard links.

## CLI

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

Commands are case-insensitive. `list` and `stat` default to `/` and to the volume respectively. SSH keys, host records, and passwords are files under `/.drive`.

`hdnfs ui` takes no arguments and needs a terminal. It lists block disks and partitions from `/sys/block`. Choosing one uses the same sudo access grant as the other commands when the device node is not writable. It then reads the `HDNFS2` magic. Magic present asks for the volume password and opens a browser. Magic absent starts initialization. Pressing `i` on that list initializes the highlighted drive even when the magic is present, through the same sudo grant and the same form. Pressing `c` changes the password when the magic is present. Pressing `w` asks for the highlighted path to be typed again, then overwrites that whole file or device with random data. The length stays the same. Esc cancels the prompt. Esc, `q`, or Ctrl-C during the overwrite stops the rest, and bytes already written stay random. The form asks for the current password and the new password twice, and a block device that is not yet writable uses that same sudo grant first. Enter on that list is unchanged. A block device or a non-empty file must be confirmed by retyping the path, and the volume password is entered twice. The form asks for a size. On a block device, a blank size uses the whole device and any other size initializes only that prefix. A new file requires a size. The browser lists the open directory, including `/.drive` when that directory exists, and can open a directory, mkdir, put, get the selected file or directory, move the entry under the cursor, delete it, grow the volume, stat, and check health. `d` opens that confirmation. Enter deletes a file or an empty directory. `r` in that dialog deletes a directory tree. Esc cancels. `e` asks for a destination path, starting from the current path, and moves the entry. `+` asks for a new size and grows the volume. When a volume is open, the top bar shows `menu`, and `m` opens `files`, `hosts`, `keys`, and `passwords`. `b` runs that check over the whole volume and repairs what it can. Esc, `q`, or Ctrl-C during the scan returns to the browser. The report stays until Enter, Esc, or `q`, and `q` there does not quit. `w` asks for a file path and writes the compact backup described below. Esc, `q`, or Ctrl-C during the copy stops it and removes the partial file. `hdnfs <backup> restore <dest>` writes that image back and fills free blocks with random data. In that browser, h and Left go to the parent directory, j, k, Up, and Down move, and l and Right open a directory. Enter does nothing there. Put opens a local file browser in the user's home directory. h and Left go to the parent directory. j, k, Up, and Down move in the list. l and Right open a directory. Space selects or unselects the cursor, and a selected directory includes its files and empty subdirectories. The selection can include files and directories from more than one host directory. Enter stores the selection in the current volume directory: a file keeps its own name, and a directory is stored under its own name. With nothing marked, Enter stores the cursor. Esc closes the file browser and drops the selection. Space in the volume browser toggles files. A directory is not selectable. Marks remain while moving between directories. `g` opens a full page of those files, smallest first. Each line is the size and the full path. With nothing marked, `g` uses the file under the cursor, or that directory when the cursor is on a directory. A directory is written as one tree, including empty directories and their modification times. j, k, Up, and Down move on that page, and `r` removes the file under the cursor. Enter confirms the remaining files and Esc cancels, leaving the marks. Two files with the same name must be reduced to one before Enter continues. Confirming opens the local file browser in the home directory, without selection marks. `l` and Right open a subdirectory. Enter opens a dialog showing that directory's full path. Enter in the dialog downloads the files there and Esc closes the dialog. The download lists every file with its name, size, and target path, and copies one file at a time from smallest to largest. The active line fills from the left as a progress bar and shows the percent at the left. A finished file moves to the bottom of the list and is marked done. A file that fails stays in the list as failed and the rest continue. Esc, `q`, or Ctrl-C during the copy cancels the rest and removes the partial file in progress. Files already written stay. The page stays until Enter, Esc, or `q`, and `q` there returns to the volume browser. Pressing `/` in the volume browser, or in the put or get file picker, opens a path field at the top of that page. The field starts empty. Typed text filters the open directory by a case-sensitive prefix. A `/` after a name enters that directory when it exists, and until that `/` the list only filters. A missing name, or a file, stays in the last directory and filters by that name. Arrow keys move in the filtered list. Tab fills the highlighted match, then cycles forward through those names. Shift+Tab cycles backward. The list stays filtered by the text already typed until the next edit. Enter keeps the directory reached. Esc closes the field and returns to the directory where `/` was pressed. Esc from the volume browser returns to the disk list. q quits. The screen stays up for every operation, including initialization. The shortcut line sits on the bottom border of the content window. A loading bar is the row under that border. Initialization shows one progress bar. `hdnfs <volume> init` prints that same bar as a single updating line on stderr. q or Ctrl-C on the bar cancels and returns to the form. Opening, listing, getting, deleting, moving, growing, mkdir, stat, and health use the same library calls as the CLI.

One put selection is one transaction. The directory entries for that selection are written once, when the copy finishes or the user cancels, and that is when it becomes durable. A crash before then leaves the previous tree. Cancelling keeps the files already staged. A file that fails to stage does not remove files staged earlier in that selection: those are committed and the failed file is not. If the final directory update itself fails, the whole selection is discarded. `hdnfs <volume> put` is still one transaction per file, and each missing parent it creates is its own transaction.

`SIZE` is a decimal integer with an optional binary suffix: `K`/`KB`/`KiB`, `M`/`MB`/`MiB`, `G`/`GB`/`GiB`, `T`/`TB`/`TiB`. A bare number is bytes. `64M` is `64 * 1024 * 1024`.

`init` of a new file creates it with mode `0600` and requires `--size`. `init` of a block device reads the device size. `--size` on a block device limits the volume to that prefix and is rejected when it is larger than the device. Omitting `--size` uses the whole device. `init` refuses a non-empty file, and refuses every block device, unless `--force` is set. With `--force`, the user must retype the volume path exactly as it was passed. `init` then fills free blocks with random data, writes the root directory and its three parity blocks, and writes all three superblock copies at generation 1.

Linux block devices are usually mode `0660` and group `disk`. When the caller cannot open one, the CLI asks for the sudo password on the terminal (no echo) and runs `setfacl -m u:<uid>:rw` on the canonical path under `/dev`. The password is passed to `sudo -S` on stdin, then wiped. The hdnfs process does not stay root. A cached sudo credential is reused with `sudo -n` and no prompt. The ACL is on that device node; unplugging the disk drops it, and the next command asks again. `init` asks only after `--force` and the path confirmation, and before the volume password. `wipe` asks for the path again, then the sudo password when the device node is not writable, and does not ask for the volume password. Every other command asks before the volume password. The volume password is a different prompt and is never sent to sudo. The library does not call sudo.

`get` holds an exclusive lock. It writes a temporary file next to the destination and renames it into place after the last byte is recovered. An existing destination file is replaced only after that. The modification time is set from the inode before the rename. When a stripe had to be rebuilt, or the bitmap was rebuilt at open, `get` writes those repaired blocks on the volume before the rename. If that write fails, the previous destination stays. The same copy can report plaintext bytes as they are written and stop before the rename when that report returns an error. A directory `get` creates the destination directory, copies each child, and sets the directory modification time after the children.

`health` holds an exclusive lock, prints a block progress line on stderr, then prints checked, repaired, unrepairable, and scrubbed counts. It exits 1 when the unrepairable count is not zero. After the repair walk it overwrites every free data block with random bytes and syncs. That scrub does not bump the generation. Ctrl-C stops the process. Repairs that already committed stay. A scrub that is interrupted leaves a mix of old and new free blocks.

`list` prints one entry per line, sorted by name:

```
d <name>
f <size> <name>
```

`stat` without a path prints the addressable size, block size, and used and free blocks. `stat` with a path prints the kind, logical size, and created and modified times in UTC (`YYYY-MM-DDTHH:MM:SSZ`).

Progress and prompts go to stderr. `list` and `stat` go to stdout. Failures print one message to stderr and exit 1. `--help` exits 0.

## Grow

`grow --size` raises `total_physical` and `data_block_count`. The allocation bitmap stays one slot wide, so the new size has to use the same bitmap geometry. New physical blocks are filled with random data before the superblock commit. The bitmap gains zero bits for those blocks. A file shorter than the new size is extended. A block device must already be at least that long. The new size has to add at least one block. Shrink is refused.

## Backup

`backup` writes a compact file. The magic is `HDNFSBK`, then the 12 KiB superblock, then each allocated physical block with its index. Allocated means both bitmap slots and every data block whose bit is set. Free data blocks are omitted. The file is not itself a volume. `restore` checks the password against the superblock before it writes, then writes the saved blocks and fills every other physical block with random data. A file that still starts with `HDNFS2` is an older raw image and is copied as that image.

## What this version leaves out

Content search, sync, and a kernel mount are not in this version.

## Tests

`cargo test` covers path rules, passwords, superblock generation choice, nested `put`, the file/directory type lock, replace, `get`, `list`, `stat`, `mkdir`, empty files, a file larger than one block, a bad password, a flipped stripe member that `get` and `health` repair, four failed members of one stripe, one or two damaged superblock copies, three damaged superblock copies, and scrubbing of freed blocks. It also covers recursive delete, rename and move, directory copy, source modification times, compact backup and restore, health scrub, grow, and wipe. Tests call the library with a tiny Argon2id parameter set. The binary has no switch for that.

`src/volume/tests/fault_tests.rs` injects bitrot on a real disk. Each test initializes a 64 MiB prefix of `/dev/sda` (96 MiB for a two-stripe replace, 128 MiB for a deep directory tree) and refuses to run unless that device is the unmounted PS8 Portable SSD, with no partitions, and the root filesystem is on nvme. The tests never pass an empty size, so they do not initialize the rest of the disk. Markers at 256 MiB and 1 GiB must still be present when a test finishes.
