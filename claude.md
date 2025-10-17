# HDNFS - Hidden File System

## Project Overview

**HDNFS** is a specialized encrypted file system implementation in Go that stores files directly on block devices (USB drives, disks) or regular files with encryption. The system is designed to "hide" files by writing them with AES-CFB encryption to a storage medium.

**Repository**: `github.com/zveinn/hdnfs`
**Language**: Go 1.22.4
**Dependencies**: `golang.org/x/term` (for terminal password input)

---

## Architecture & Design

### Core Concept

HDNFS implements a simple flat file system with:
- **Fixed-size metadata region** at the beginning of the storage device (200KB)
- **Fixed-size file slots** (50KB per file, max 1000 files)
- **AES-CFB encryption** for all stored data (metadata + files)
- **JSON-based metadata** structure

### Storage Layout

```
[0 - 200KB]                    : Encrypted Metadata (file index, names, sizes)
[200KB - 250KB]                : File slot 0
[250KB - 300KB]                : File slot 1
...
[49,800KB - 49,850KB]          : File slot 999
```

Total capacity: **~50MB** (200KB metadata + 1000 × 50KB files)

### Key Constants (structs_globals.go:8-15)

```go
META_FILE_SIZE      = 200_000      // 200KB for metadata
MAX_FILE_SIZE       = 50_000       // 50KB per file
MAX_FILE_NAME_SIZE  = 100          // Max filename length
TOTAL_FILES         = 1000         // Total file slots
ERASE_CHUNK_SIZE    = 1_000_000    // 1MB chunks for erasing
OUT_OF_BOUNDS_INDEX = 99999999     // Sentinel for "append" mode
```

### Data Structures

#### Meta Structure (structs_globals.go:19-26)
```go
type Meta struct {
    Files [TOTAL_FILES]File  // Fixed array of 1000 file entries
}

type File struct {
    Name string  // Filename (max 100 bytes)
    Size int     // Actual file size in bytes
}
```

#### File Interface (structs_globals.go:28-34)
The code abstracts file operations through an interface `F` to support both real devices and regular files.

---

## Module Breakdown

### 1. Main Entry Point (main.go & cmd/hdnfs/main.go)

**Purpose**: CLI argument parsing and command routing

**Command Structure**:
```bash
./hdnfs [device] [cmd] [params...]
```

**Available Commands**:
- `init [mode]` - Initialize the file system
- `add [path] [new_name] [index]` - Add/overwrite a file
- `get [index] [path]` - Extract a file
- `del [index]` - Delete a file
- `list [filter]` - List all files (with optional name filter)
- `stat` - Display device stats (UNIMPLEMENTED)
- `erase [index]` - Overwrite device data from index
- `sync [target_device]` - Clone filesystem to another device

**Key Features**:
- Simple switch-case command dispatcher (main.go:47-131)
- Comprehensive help menu with usage examples (main.go:134-195)
- Basic parameter validation

---

### 2. Encryption (crypt.go)

**Algorithm**: AES-CFB (Cipher Feedback Mode)
**Key Source**: Environment variable `HDNFS` (must be ≥32 bytes)

#### Key Functions:

**GetEncKey()** (crypt.go:13-29)
- Retrieves encryption key from `HDNFS` environment variable
- Caches key in global `KEY` variable
- Panics if key is missing or <32 bytes
- **SECURITY ISSUE**: No key derivation function (KDF) - raw environment variable used directly

**Encrypt()** (crypt.go:50-65)
- Creates AES cipher block
- Generates random IV (Initialization Vector)
- Returns: `[IV (16 bytes)][encrypted data]`
- **CRITICAL**: IV is prepended to ciphertext

**Decrypt()** (crypt.go:31-48)
- Extracts IV from first 16 bytes
- Decrypts remaining data using CFB mode
- **ISSUE**: No authentication (MAC) - vulnerable to tampering

---

### 3. Metadata Management (meta.go)

#### InitMeta() (meta.go:43-77)
**Purpose**: Initialize empty filesystem

**Process**:
1. If mode="file", overwrites entire file with zeros (using Overwrite)
2. Creates empty `Meta` struct
3. Marshals to JSON
4. Encrypts metadata
5. Prepends 4-byte length header (big-endian)
6. Pads to 200KB
7. Writes to offset 0

**Format**: `[4-byte length][encrypted JSON metadata][padding]`

#### WriteMeta() (meta.go:11-41)
**Purpose**: Update metadata on device

**Process**:
1. Marshal `Meta` to JSON
2. Encrypt the JSON
3. Prepend 4-byte length header
4. Pad to META_FILE_SIZE (200KB)
5. Write at offset 0

**Critical Point**: Every file add/delete requires full metadata rewrite

#### ReadMeta() (meta.go:79-114)
**Purpose**: Read and decrypt metadata

**Process**:
1. Read 200KB from offset 0
2. Extract length from first 4 bytes
3. Decrypt metadata using length
4. Unmarshal JSON to `Meta` struct
5. Exit if metadata not found (byte 4 == 0)

---

### 4. File Operations

#### Add() (add.go:9-96)
**Purpose**: Add or overwrite a file

**Parameters**:
- `path`: Source file path
- `name`: Stored filename
- `index`: Slot index (or OUT_OF_BOUNDS_INDEX for next available)

**Process**:
1. Stat source file
2. Validate filename length (≤100 bytes)
3. Read existing metadata
4. Find available slot (or use provided index)
5. Read file contents
6. Calculate seek position: `META_FILE_SIZE + (index × MAX_FILE_SIZE)`
7. Encrypt file data
8. **Validate encrypted size < 50KB** (add.go:61-64)
9. Pad encrypted data to 50KB (add.go:66-67)
10. Write to device
11. Update metadata

**CRITICAL ISSUE**: Line 66 pads to META_FILE_SIZE (200KB) instead of MAX_FILE_SIZE (50KB)
```go
missing := META_FILE_SIZE - len(fb)  // BUG: Should be MAX_FILE_SIZE
```

#### Get() (read.go:7-38)
**Purpose**: Extract and decrypt a file

**Process**:
1. Read metadata
2. Get file entry at index
3. Seek to: `META_FILE_SIZE + (index × MAX_FILE_SIZE)`
4. Read `file.Size` bytes
5. Decrypt data
6. Write to output path

#### Del() (del.go:8-40)
**Purpose**: Delete a file

**Process**:
1. Read metadata
2. Clear metadata entry (Size=0, Name="")
3. Seek to file slot
4. Overwrite slot with 50KB of zeros
5. Update metadata

---

### 5. Listing & Filtering (list.go)

#### List() (list.go:8-25)
**Purpose**: Display all stored files

**Features**:
- Iterates through all 1000 slots
- Skips empty slots (Name=="")
- Optional substring filter on filenames
- Displays: index, size, name

**Output Format**:
```
----------- FILE LIST -----------------
 index size  name
--------------------------------------
 0     1234  document.txt
 5     8921  image.jpg
--------------------------------------
```

---

### 6. Device Synchronization (sync.go)

#### Sync() (sync.go:9-21)
**Purpose**: Clone entire filesystem to another device

**Process**:
1. Read source metadata
2. Write metadata to destination
3. For each file slot (all 1000):
   - Read 50KB block from source
   - Write block to destination (even empty slots)

**INEFFICIENCY**: Copies all 1000 slots regardless of occupancy

#### ReadBlock() / WriteBlock() (sync.go:23-70)
Helper functions for block-level copying

---

### 7. Data Erasure (overwrite.go)

#### Overwrite() (overwrite.go:10-46)
**Purpose**: Securely erase device by writing zeros

**Parameters**:
- `start`: Starting byte offset
- `end`: Ending byte offset (or math.MaxUint64 for full disk)

**Process**:
1. Write zeros in 1MB chunks
2. Call Sync() after each chunk
3. Adaptive sleep based on write speed:
   - If write takes >500ms: sleep 3 seconds
   - Else: sleep 5ms
4. Continue until reaching `end` or "no space left" error

**Use Cases**:
- Initialize file-based storage
- Secure device wiping
- Prepare device before use

---

### 8. Interactive Mode (cmd/interactive/main.go)

**Status**: EXPERIMENTAL (marked 7 times in comments)

**Purpose**: Interactive shell for HDNFS operations

**Features**:
1. Prompts for password via `term.ReadPassword`
2. Sets global `KEY` variable (bypasses environment variable)
3. Reads commands from stdin in loop
4. Parses space-separated arguments
5. Calls hdnfs.Main() for each command

**SECURITY CONCERNS**:
- Uses goto loop (goto AGAIN)
- Direct key injection into global variable
- No session timeout
- Password remains in memory

---

### 9. Testing & Debugging (cat.go, testing/main.go)

#### cat.go
**Purpose**: Debug utility to inspect raw bytes

**Cat()** (cat.go:8-23):
- Reads arbitrary byte range from device
- Prints both hex and string representation
- Used for manual inspection

#### testing/main.go
Contains various commented-out test operations:
- Direct device access (`/dev/sda`)
- Metadata initialization
- File operations
- Raw byte inspection

**WARNING**: Hardcoded `/dev/sda` could cause data loss if run accidentally

---

### 10. Statistics (stat.go)

**Status**: COMPLETELY UNIMPLEMENTED

**Current State**:
- Empty function with commented-out code
- Would show device/file statistics
- Needs implementation

---

## Critical Issues & Problems

### 🔴 CRITICAL SECURITY ISSUES

#### 1. No Authenticated Encryption (crypt.go)
**Problem**: Uses AES-CFB without MAC (Message Authentication Code)

**Impact**:
- Vulnerable to bit-flipping attacks
- No integrity verification
- Attacker can modify encrypted data without detection

**Recommendation**: Use AES-GCM or add HMAC for authentication

#### 2. No Key Derivation Function (crypt.go:13-29)
**Problem**: Encryption key taken directly from environment variable

**Impact**:
- Weak passwords create weak keys
- No salt or iteration count
- Vulnerable to brute force

**Recommendation**: Use PBKDF2, Argon2, or scrypt

#### 3. Global Mutable Key Variable (crypt.go:11)
**Problem**: `var KEY = []byte{}`

**Impact**:
- Race conditions in concurrent use
- Memory not cleared after use
- Key visible in memory dumps

**Recommendation**: Use secure key management with zeroization

#### 4. Interactive Mode Key Handling (cmd/interactive/main.go:34)
**Problem**: Password stored in global variable indefinitely

**Impact**:
- Key persists in memory
- No session timeout
- Potential memory leakage

---

### 🟠 MAJOR BUGS

#### 1. Buffer Size Mismatch in Add() (add.go:66)
**Problem**:
```go
missing := META_FILE_SIZE - len(fb)  // Should be MAX_FILE_SIZE
```

**Impact**:
- Pads encrypted files to 200KB instead of 50KB
- Causes buffer overflow or corruption
- Write will exceed allocated slot (50KB)

**Fix**:
```go
missing := MAX_FILE_SIZE - len(fb)
```

#### 2. File Size Validation After Encryption (add.go:61-64)
**Problem**: Checks if encrypted size >= 50KB, but encryption adds 16-byte IV

**Impact**:
- Maximum stored file is ~49,984 bytes (not 50KB)
- AES-CFB adds IV overhead
- Users might not understand size limits

**Recommendation**: Document actual usable size (49,984 bytes)

#### 3. No Bounds Checking on Index (multiple files)
**Problem**: Limited validation of user-provided indices

**Examples**:
- `Get()` (read.go:7): No check if `index >= TOTAL_FILES`
- Can cause panic or read invalid memory

**Fix**: Add validation:
```go
if index < 0 || index >= TOTAL_FILES {
    PrintError("index out of bounds", nil)
    return
}
```

#### 4. Stat Function Unimplemented (stat.go:5-14)
**Problem**: Function exists but does nothing

**Impact**: Users expect it to work based on help menu

**Recommendation**: Implement or remove from help menu

---

### 🟡 DESIGN ISSUES

#### 1. Fixed File Size Limitation
**Problem**: All files limited to 50KB (actually ~49,984 bytes)

**Impact**:
- Cannot store larger files
- No chunking mechanism
- Wastes space for small files

**Recommendation**: Consider variable-sized blocks or chunking

#### 2. Inefficient Metadata Updates
**Problem**: Every file operation rewrites entire 200KB metadata

**Impact**:
- Slow for frequent updates
- Increased device wear
- Unnecessary I/O

**Recommendation**: Use more granular metadata updates or caching

#### 3. Sync Copies All Slots (sync.go:13-20)
**Problem**: Copies all 1000 slots (50MB) even if mostly empty

**Impact**:
- Wastes time and bandwidth
- Unnecessary writes
- Could copy empty slots only when needed

**Recommendation**: Skip empty slots during sync

#### 4. No Fragmentation Handling
**Problem**: Deleted files leave holes, but no compaction

**Impact**:
- Eventually runs out of slots even with space
- No defragmentation utility

**Recommendation**: Add compaction command

#### 5. Weak Random Seed (overwrite.go:39)
**Problem**: Error message has typo: `"no space left of device"`

**Minor Issue**: Just a typo in error handling

---

### 🟡 CODE QUALITY ISSUES

#### 1. Global Variables (main.go:11-18)
**Problem**: Unused globals (`device`, `remove`, `start`, `diskPointer`)

**Impact**: Confusing code, suggests refactoring in progress

#### 2. Commented Debug Code (testing/main.go, stat.go)
**Problem**: Large blocks of commented code

**Impact**: Clutters codebase, unclear if intentional

**Recommendation**: Remove or document

#### 3. Magic Numbers
**Problem**: Hardcoded values throughout (4, 16, etc.)

**Recommendation**: Use named constants

#### 4. Error Handling Inconsistency
**Problem**: Mix of panic, os.Exit, and PrintError

**Examples**:
- `crypt.go:19,23`: panic
- `meta.go:100`: os.Exit(1)
- `add.go:12`: PrintError + return

**Recommendation**: Standardize error handling strategy

#### 5. Goto Usage (cmd/interactive/main.go:36,48)
**Problem**: Uses `goto AGAIN` for main loop

**Impact**: Difficult to follow, anti-pattern in Go

**Recommendation**: Use proper for loop

---

### 🔵 USABILITY ISSUES

#### 1. Typo in README.md:7
**Problem**: `lates` should be `latest`

**Fix**: Update download link

#### 2. Typo in Help Menu (main.go:169)
**Problem**: `[index:optionl]` should be `[index:optional]`

#### 3. No Progress Indication
**Problem**: Long operations (erase, sync) have minimal feedback

**Impact**: User doesn't know if tool is frozen

**Recommendation**: Add progress bars or percentages

#### 4. Cryptic Error Messages
**Problem**: Messages like "Short write" don't explain issue

**Recommendation**: Add contextual information

#### 5. No Dry-Run Mode
**Problem**: Destructive operations (erase) have no preview

**Recommendation**: Add `--dry-run` flag

---

### 🔵 MISSING FEATURES

#### 1. No File Compression
**Observation**: 50KB limit could be extended with compression

**Recommendation**: Add optional compression (gzip)

#### 2. No Backup/Restore
**Problem**: No way to backup metadata separately

**Recommendation**: Add metadata export/import

#### 3. No Integrity Verification
**Problem**: No way to verify device hasn't been corrupted

**Recommendation**: Add checksum verification command

#### 4. No Filesystem Statistics
**Problem**: Can't see space usage, fragmentation

**Recommendation**: Implement stat command properly

#### 5. Remote Server Support (README TODO)
**Problem**: Listed in TODO but not implemented

**Impact**: Cannot use over network

---

## File Reference Map

```
hdnfs/
├── main.go                    # Main entry point, CLI parsing
├── structs_globals.go         # Constants, data structures
├── crypt.go                   # AES-CFB encryption/decryption
├── meta.go                    # Metadata read/write/init
├── add.go                     # Add files to filesystem
├── read.go                    # Extract files (Get command)
├── del.go                     # Delete files
├── list.go                    # List all files
├── sync.go                    # Clone filesystem
├── overwrite.go               # Secure erase utility
├── cat.go                     # Debug byte inspector
├── stat.go                    # Statistics (unimplemented)
├── go.mod                     # Module definition
├── go.sum                     # Dependency checksums
├── README.md                  # User documentation
├── .goreleaser.yaml           # Release configuration
├── .gitignore                 # Git ignore rules
├── cmd/
│   ├── hdnfs/main.go          # Thin wrapper for main CLI
│   └── interactive/main.go    # Experimental interactive mode
└── testing/
    └── main.go                # Manual testing utilities
```

---

## Usage Examples

### Basic Workflow

```bash
# 1. Set encryption key (32+ bytes required)
export HDNFS="my-super-secret-key-is-32-bytes!"

# 2. Initialize device
./hdnfs /dev/sdb init device        # For USB/disk
./hdnfs ./mystore.dat init file     # For regular file

# 3. Add files
./hdnfs /dev/sdb add document.txt stored_doc.txt
./hdnfs /dev/sdb add image.jpg my_image.jpg 5  # At specific index

# 4. List files
./hdnfs /dev/sdb list
./hdnfs /dev/sdb list "doc"         # Filter by name

# 5. Extract file
./hdnfs /dev/sdb get 0 ./output.txt

# 6. Delete file
./hdnfs /dev/sdb del 0

# 7. Clone to another device
./hdnfs /dev/sdb sync /dev/sdc

# 8. Secure erase
./hdnfs /dev/sdb erase 0            # Erase from beginning
```

---

## Security Recommendations

### Immediate Fixes Required:

1. **Switch to AES-GCM** for authenticated encryption
2. **Add PBKDF2/Argon2** for key derivation
3. **Fix buffer overflow** in add.go:66
4. **Add bounds checking** on all index operations
5. **Implement secure key storage** (avoid globals)

### Best Practices:

1. **Use secure deletion** (multiple overwrite passes)
2. **Add version field** to metadata (for future compatibility)
3. **Implement journaling** (for crash recovery)
4. **Add checksums** to each file entry
5. **Consider using established crypto libraries** (NaCl/libsodium)

---

## Performance Characteristics

### Read Performance:
- **Metadata read**: 200KB + decryption overhead
- **File read**: Direct seek to slot, minimal overhead
- **Bottleneck**: Encryption/decryption operations

### Write Performance:
- **Add file**: Read metadata (200KB) + Write file (50KB) + Write metadata (200KB)
- **Total I/O per add**: ~450KB
- **Delete file**: Read metadata + Write zeros (50KB) + Write metadata
- **Total I/O per delete**: ~300KB

### Sync Performance:
- **Total data copied**: 50MB (all 1000 slots + metadata)
- **Time**: Depends on device speed, no optimization for sparse data

---

## Future Development Suggestions

### Short Term:
1. Fix critical buffer overflow bug (add.go:66)
2. Implement stat command
3. Add bounds checking everywhere
4. Fix typos in documentation

### Medium Term:
1. Switch to authenticated encryption (AES-GCM)
2. Add key derivation function
3. Implement progress indicators
4. Add integrity verification

### Long Term:
1. Variable file sizes / chunking for large files
2. Compression support
3. Remote server support (per TODO)
4. Journaling for crash recovery
5. Metadata compaction/defragmentation

---

## Testing Recommendations

### Unit Tests Needed:
1. Encryption/decryption round-trip
2. Metadata serialization
3. Index calculations
4. Boundary conditions (full filesystem, max filename)

### Integration Tests Needed:
1. Full workflow (init → add → list → get → del)
2. Sync between devices
3. Error handling (corrupted metadata, disk full)
4. Concurrent access (if supported)

### Security Tests Needed:
1. Tamper detection (modify encrypted data)
2. Key strength validation
3. Information leakage (filenames, sizes)

---

## Build & Release

### Build Commands:
```bash
# Install directly
go install github.com/zveinn/hdnfs/cmd/hdnfs@latest

# Local build
go build -o hdnfs ./cmd/hdnfs

# Release (requires GITHUB_TOKEN)
goreleaser release --clean

# Snapshot build (no release)
goreleaser build --snapshot --clean
```

### Release Configuration (.goreleaser.yaml):
- **Platforms**: Linux, Windows, macOS
- **Architectures**: amd64, arm64
- **Output**: `./builds/`
- **Mode**: Draft releases with artifact replacement

---

## Dependencies Analysis

### Direct Dependencies:
- **golang.org/x/term** (v0.26.0)
  - Purpose: Terminal password input for interactive mode
  - Used in: `cmd/interactive/main.go:23`

### Indirect Dependencies:
- **golang.org/x/sys** (v0.27.0)
  - Required by golang.org/x/term
  - System call wrappers

### Standard Library Usage:
- `crypto/aes`: AES encryption
- `crypto/cipher`: Cipher modes (CFB)
- `crypto/rand`: Random IV generation
- `encoding/json`: Metadata serialization
- `encoding/binary`: Integer encoding
- `os`: File/device operations
- `bufio`: Interactive mode input
- `strings`: String manipulation
- `strconv`: String/integer conversion
- `fmt`: Formatting
- `log`: Logging

---

## Conclusion

HDNFS is a functional but basic encrypted filesystem implementation with several critical security vulnerabilities and bugs. The code is relatively simple and easy to understand, but requires significant improvements before production use:

### Strengths:
- Simple, understandable codebase
- Direct block device access
- AES encryption for confidentiality
- Cross-platform support

### Critical Weaknesses:
- No authenticated encryption (tampering possible)
- Buffer overflow bug in file addition
- Fixed size limitations (50KB per file)
- No key derivation (weak password protection)
- Inefficient metadata management

### Recommended Priority:
1. **URGENT**: Fix buffer overflow (add.go:66)
2. **HIGH**: Switch to AES-GCM or add HMAC
3. **HIGH**: Add key derivation (PBKDF2/Argon2)
4. **MEDIUM**: Implement bounds checking
5. **MEDIUM**: Optimize sync operation
6. **LOW**: Implement stat command
7. **LOW**: Fix typos and improve documentation

**Overall Assessment**: The project demonstrates understanding of encryption and file I/O, but needs security hardening and bug fixes before being suitable for protecting sensitive data.
