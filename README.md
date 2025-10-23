# HDNFS - Hidden File System

A secure, encrypted file storage system for USB drives, block devices, and files. HDNFS provides military-grade encryption (AES-256-GCM) with a simple command-line interface for storing, retrieving, and managing encrypted files.

## Features

- **Strong Encryption**: AES-256-GCM authenticated encryption with Argon2id key derivation
- **Password Protection**: Secure password prompting via stdin (no environment variables)
- **Flexible Storage**: Works with USB drives, block devices, or regular files
- **Simple Architecture**: Flat storage model with 1000 fixed-size slots
- **Data Integrity**: SHA256 checksums and authenticated encryption
- **Device Sync**: Replicate entire encrypted filesystems between devices
- **Secure Erase**: Instant file truncation or device zero-write for secure data destruction
- **Content Search**: Search through encrypted files by filename or content
- **Silent Mode**: Scriptable with `--silent` flag for automation

## Quick Start

### Installation

#### Download Binary
```bash
# Download from releases
https://github.com/zveinn/hdnfs/releases/latest
```

#### Install with Go
```bash
go install github.com/zveinn/hdnfs/cmd/hdnfs@latest
```

#### Build from Source
```bash
# Snapshot build
goreleaser build --snapshot --clean

# Release build (requires GITHUB_TOKEN)
goreleaser release --clean
```

### Setup and Password Management

#### Password System

HDNFS uses secure password prompting via stdin for maximum security:

- **Secure Input**: Passwords are entered via terminal (no echo) using secure input methods
- **No Environment Variables**: Passwords are never stored in environment variables or config files
- **Memory Caching**: Password is cached in memory for the duration of each command execution
- **Single Prompt**: You'll only be prompted once per command, even for operations that require multiple encryption/decryption steps
- **Minimum Length**: Passwords must be at least 12 characters long
- **Key Derivation**: Your password is used with Argon2id to derive encryption keys

#### Example Usage

```bash
# Initialize a file-based storage
./hdnfs storage.hdnfs init file
# You'll be prompted: "Enter password: "
# Type your password (it won't be visible) and press Enter

# For a USB device
sudo ./hdnfs /dev/sdb1 init device
# You'll be prompted: "Enter password: "
```

**Important Notes**:
- Use the **same password** for a device across all operations (init, add, get, list, etc.)
- If you use different passwords, you won't be able to decrypt existing files
- Choose a strong password - your data security depends on it
- Store your password securely - if you forget it, your data cannot be recovered

## Usage

### Command Syntax
```bash
hdnfs [device] [command] [parameters...]
```

### Commands

#### Initialize Storage
```bash
# Initialize a block device
hdnfs /dev/sdb1 init device

# Initialize a file
hdnfs storage.hdnfs init file
```

#### Add Files
```bash
# Add file with auto-indexing
hdnfs /dev/sdb1 add /path/to/file.txt "My Secret File"

# Add file to specific slot (0-999)
hdnfs /dev/sdb1 add /path/to/file.txt "My File" 42

# Overwrite existing file at slot
hdnfs /dev/sdb1 add /path/to/new.txt "Updated" 42
```

#### List Files
```bash
# List all files
hdnfs /dev/sdb1 list

# List files matching filter
hdnfs /dev/sdb1 list secret

# Silent mode for scripting
hdnfs --silent /dev/sdb1 list | grep important
```

#### Retrieve Files
```bash
# Get file from slot 5
hdnfs /dev/sdb1 get 5 /tmp/recovered.txt

# Extract multiple files
for i in {0..10}; do
    hdnfs /dev/sdb1 get $i "/tmp/file_$i.bin"
done
```

#### Delete Files
```bash
# Delete file at index 5 (zeros slot)
hdnfs /dev/sdb1 del 5
```

#### Sync Devices
```bash
# Copy all files from source to destination
hdnfs /dev/sdb1 sync /dev/sdc1

# Files remain encrypted with same password
```

#### Device Statistics
```bash
# Show device info
hdnfs /dev/sdb1 stat
```

#### Secure Erase
```bash
# For files: instant truncation to 0 bytes
hdnfs storage.hdnfs erase

# For devices: overwrites entire device with zeros
hdnfs /dev/sdb1 erase
```

#### Search Files
```bash
# Search filenames only (fast, no decryption needed)
hdnfs /dev/sdb1 search-name "document"

# Search all file contents for a phrase (decrypts and scans each file)
hdnfs /dev/sdb1 search "password"

# Search specific file by index (faster when you know which file to search)
hdnfs /dev/sdb1 search "secret" 5

# All searches are case-insensitive
hdnfs /dev/sdb1 search-name "PDF"        # matches "report.pdf", "Data.PDF", etc.
hdnfs /dev/sdb1 search "confidential"    # matches "Confidential", "CONFIDENTIAL", etc.
```

### Global Flags

- `--silent` or `-silent`: Suppress informational output (errors still shown)

## Technical Specifications

### Storage Limits
- **Maximum Files**: 1000
- **Maximum File Size**: ~50KB per file
- **Maximum Filename Length**: 100 characters
- **Minimum Device Size**: ~50.2MB
- **Metadata Size**: 200KB

### Security

#### Password Management
- **Input Method**: Secure stdin prompting with no echo (uses `golang.org/x/term`)
- **Storage**: Never stored in environment variables, config files, or on disk
- **Memory Handling**: Cached in memory during command execution, zeroed out on cleanup
- **Validation**: Minimum 12 characters enforced

#### Encryption
- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: Argon2id
  - Time cost: 3 iterations
  - Memory cost: 64MB
  - Threads: 4
  - Output: 32-byte key
- **Random Elements**: 12-byte nonce per file + 32-byte salt per device
- **Integrity**: SHA256 checksums on metadata
- **Authentication**: GCM mode provides AEAD (Authenticated Encryption with Associated Data)

### Storage Layout
```
[0 - 199,999]           Metadata block (200KB)
[200,000 - 249,999]     File slot 0 (50KB)
[250,000 - 299,999]     File slot 1 (50KB)
...
[50,199,000 - 50,248,999] File slot 999 (50KB)
```

### Metadata Structure
```
Header (45 bytes):
  - Magic: "HDNFS" (5 bytes)
  - Version: 2 (1 byte)
  - Reserved: (2 bytes)
  - Salt: 32 bytes (random, unique per device)
  - Encrypted Length: 4 bytes

Encrypted Metadata (~166KB max):
  - JSON structure with 1000 file entries
  - Each entry: {Name: string, Size: int}

SHA256 Checksum: 32 bytes
Padding: Variable
```

## Examples

### Basic Workflow
```bash
# Create test storage
dd if=/dev/zero of=test.hdnfs bs=1M count=100
./hdnfs test.hdnfs init file
# Enter password: *************** (minimum 12 characters)

# Add files (same password will be prompted)
./hdnfs test.hdnfs add document.pdf "Important Document"
# Enter password: ***************

./hdnfs test.hdnfs add photo.jpg "Family Photo" 10
# Enter password: ***************

# List files
./hdnfs test.hdnfs list
# Enter password: ***************

# Retrieve files
./hdnfs test.hdnfs get 0 /tmp/document.pdf
# Enter password: ***************

./hdnfs test.hdnfs get 10 /tmp/photo.jpg
# Enter password: ***************

# Delete file
./hdnfs test.hdnfs del 0
# Enter password: ***************

# Verify
./hdnfs test.hdnfs list
# Enter password: ***************
```

**Note**: Each command prompts for the password once. Use the same password for all operations on a device.

### Backup to Another Device
```bash
# Create backup
dd if=/dev/zero of=backup.hdnfs bs=1M count=100
./hdnfs primary.hdnfs sync backup.hdnfs

# Verify backup
./hdnfs backup.hdnfs list
```

### Batch Operations
```bash
#!/bin/bash
# Each command in the loop will prompt for password
# Consider using expect or similar tools for automation

# Add all PDFs from a directory
for file in /path/to/documents/*.pdf; do
    filename=$(basename "$file")
    ./hdnfs storage.hdnfs add "$file" "$filename"
    # Enter password: *************** (prompted each time)
done

# List added files
./hdnfs storage.hdnfs list pdf
# Enter password: ***************
```

**Automation Tip**: For true batch automation without multiple password prompts, consider:
- Using `expect` scripts to automate password entry
- Wrapping multiple operations in a Go program that can cache the password
- Pre-loading the password cache programmatically in your own wrapper

### Silent Mode for Scripts
```bash
# Silent add
./hdnfs --silent storage.hdnfs add secret.txt "Secret"

# Silent list with processing
./hdnfs --silent storage.hdnfs list | awk '{print $3}' > filenames.txt
```

### Searching Files
```bash
# Find files by name (no decryption, very fast)
./hdnfs storage.hdnfs search-name "report"

# Search all file contents for a keyword
./hdnfs storage.hdnfs search "password"

# Search specific file by index (faster, searches only one file)
./hdnfs storage.hdnfs search "confidential" 5

# Combine with silent mode for scripting
./hdnfs --silent storage.hdnfs search "secret"
```

## Security Considerations

### Strengths
- **Secure Password Input**: Passwords entered via stdin with no echo, never stored in environment or files
- **Memory Safety**: Passwords zeroed out in memory after use
- **Strong Encryption**: AES-256-GCM with authenticated encryption prevents tampering
- **Key Derivation**: Argon2id resists brute-force and GPU attacks
- **Random Nonces**: Each encryption uses unique random nonce
- **Data Authentication**: GCM mode detects any modification attempts
- **Metadata Protection**: Filenames and sizes encrypted

### Limitations
- **Password Security**: Device security depends on password strength and memory
- **Terminal Required**: Password prompting requires an interactive terminal (stdin)
- **No Compression**: Files may increase slightly due to encryption overhead
- **File Size Observable**: Encrypted sizes visible in metadata (reveals approximate plaintext size)
- **Memory Loading**: Entire files loaded into memory during operations
- **Fixed Capacity**: 1000 file limit, 50KB per file
- **Manual Entry**: Each command execution requires password re-entry

### Best Practices
1. **Password Management**:
   - Use strong passwords (≥12 characters, mixed case, numbers, symbols)
   - Store password securely in a password manager
   - Never share passwords or write them down
   - Use unique passwords for each HDNFS device

2. **Operational Security**:
   - Keep devices physically secure
   - Use `sync` command for backups
   - Use `erase` before disposing of devices
   - Verify files after adding: `get` and compare checksums
   - Clear terminal history if password accidentally typed in command

3. **Automation Security**:
   - For scripts, use `expect` or similar tools carefully
   - Never hardcode passwords in scripts
   - Consider building custom wrappers that securely manage password prompting

## Architecture

### Core Components

**Password Management** (`password.go`):
- `PromptPassword()`: Secure stdin password input with no echo (uses `golang.org/x/term`)
- `GetPassword()`: Returns cached password or prompts if not set
- `ClearPasswordCache()`: Zeros out password in memory
- `SetPasswordForTesting()`: Test-only password injection

**Encryption** (`crypt.go`):
- `GetEncKey()`: Retrieves password via secure prompting
- `DeriveKey()`: Argon2id key derivation from password
- `EncryptGCM()`: AES-GCM encryption with random nonce
- `DecryptGCM()`: AES-GCM decryption with authentication
- `GenerateSalt()`: Cryptographically secure random salt generation
- `ComputeChecksum()`: SHA256 checksum computation

**Metadata** (`meta.go`):
- `InitMeta()`: Initialize filesystem with empty metadata
- `ReadMeta()`: Read and decrypt metadata from device
- `WriteMeta()`: Encrypt and write metadata to device
- Validates magic number, version, and checksums

**Operations**:
- `add.go`: Add/overwrite files
- `read.go`: Retrieve and decrypt files
- `del.go`: Delete files and zero slots
- `list.go`: Display file listings
- `search.go`: Search filenames and file contents
- `sync.go`: Synchronize devices
- `stat.go`: Show device statistics
- `overwrite.go`: Secure erase operations

### Data Flow

**Password Flow**:
```
User Command → Prompt Password (stdin, no echo) → Cache in Memory → Derive Key (Argon2id) → Use for Encryption/Decryption → Zero Memory on Exit
```

**Adding a File**:
```
Get Password → Source File → Read → Encrypt (AES-GCM) → Pad to 50KB → Write to Slot → Update Metadata
```

**Retrieving a File**:
```
Get Password → Read Metadata → Read Encrypted Slot → Decrypt (AES-GCM) → Verify → Write to Output
```

**Searching Files**:
```
Filename Search: Get Password → Read Metadata → Compare Names (No Decryption)
Content Search:  Get Password → Read Metadata → For Each File: Decrypt → Scan Lines → Match Pattern
```

## Troubleshooting

### "Invalid HDNFS magic number"
- Device not initialized. Run `hdnfs [device] init`

### "Decryption failed"
- **Wrong password entered** - Make sure you're using the exact same password that was used during initialization
- Corrupted data. Check device integrity
- Different device or not initialized yet

### "Password must be at least 12 characters long"
- Your password is too short
- Choose a password with 12 or more characters

### "Failed to read password"
- stdin is not available (non-interactive environment)
- Terminal doesn't support password input
- Try running from an interactive terminal

### "File too large"
- File exceeds 50KB limit after encryption
- Compress file before adding, or split into parts

### "Filesystem is full"
- All 1000 slots occupied
- Delete unused files with `del` command

### Permission Denied
- Use `sudo` for block devices
- Check file permissions for file-based storage

### Password Prompting Issues in Scripts
- Batch scripts will prompt for password on each command
- Consider using `expect` for automation
- Or wrap operations in a custom Go program

## Testing

The project includes a comprehensive test suite:

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run specific test
go test -run TestAdd

# Run benchmarks
go test -bench=.
```

Test coverage includes:
- Password management and caching
- Encryption/decryption validation
- Metadata integrity checks
- File operations (add, get, delete)
- Search operations (filename and content search)
- Edge cases and error handling
- Large file handling
- Synchronization logic
- Concurrent access patterns

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

See LICENSE file for details.

## Support

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/zveinn/hdnfs/issues
- Documentation: https://github.com/zveinn/hdnfs

---

**Warning**: This software is provided as-is. Always keep backups of important data. Test thoroughly before using in production environments.
