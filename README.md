# hidden file system
This hides your files.

# Install

## Download
 - https://github.com/zveinn/hdnfs/releases/lates

## golang
```bash
go install github.com/zveinn/hdnfs/cmd/hdnfs@latest

```

# How To 
# ./hdnfs --help

# Encryption key
```
export HDNFS=[YOUR 32 BYTE KEY]
```

# Building
 - $ goreleaser release --clean ( add GITHUB_TOKEN )
 - $ goreleaser build --snapshot --clean 

# TODO (maybe)
 - Random byte erase method
 - Remote server support

