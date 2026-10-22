use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    self, derive_kek, fill_random, open, random_bytes, random_nonce, seal, unwrap_key, wrap_key,
    KdfParams, SecretBuf,
};
use crate::error::{Error, Result};
use crate::format::{
    bitmap_len, block_aad, block_offset, decode_body, decode_entries, decode_inode_record,
    decode_superblock_header, dek_aad, div_ceil, encode_body, encode_entries, encode_inode_record,
    encode_superblock, file_key_aad, geometry, inode_chain_blocks, mask_bitmap, prefer_index,
    sb_aad, sealed_body, validate_body, InodeRecord, RawEntry, SuperBody, SuperHeader, BLOCK_SIZE,
    BODY_PLAIN_LEN, CHAIN_END, KIND_DIR, KIND_FILE, MAGIC, MAX_DIR_BYTES, PAYLOAD, PURPOSE_BITMAP,
    PURPOSE_DIR, PURPOSE_FILE, PURPOSE_INODE, SUPER_SIZE,
};
use crate::pathutil::{display_path, parse_path};
use crate::timefmt::now_unix;
use crate::unixutil;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
}

impl Kind {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            KIND_DIR => Ok(Kind::Dir),
            KIND_FILE => Ok(Kind::File),
            _ => Err(Error::Corrupt("kind".into())),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Kind::Dir => KIND_DIR,
            Kind::File => KIND_FILE,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Dir => "directory",
            Kind::File => "file",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stat {
    Volume {
        size: u64,
        block_size: u64,
        data_blocks: u64,
        used_blocks: u64,
        free_blocks: u64,
        free_payload_bytes: u64,
    },
    Node {
        path: String,
        kind: Kind,
        size: u64,
        created: i64,
        modified: i64,
    },
}

pub struct InitOptions<'a> {
    pub path: &'a Path,
    pub password: &'a str,
    pub size: Option<u64>,
    pub force: bool,
    pub kdf: KdfParams,
    /// Called with stage, completed MiB, and total MiB. `None` stays quiet.
    /// Returning an error stops initialization.
    pub progress: Option<&'a mut dyn FnMut(&str, u64, u64) -> Result<()>>,
}

struct Inode {
    id: u64,
    kind: Kind,
    created: i64,
    modified: i64,
    size: u64,
    file_key: Zeroizing<[u8; 32]>,
    content_blocks: Vec<u64>,
    stored_at: u64,
}

impl Clone for Inode {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            kind: self.kind,
            created: self.created,
            modified: self.modified,
            size: self.size,
            file_key: self.file_key.clone(),
            content_blocks: self.content_blocks.clone(),
            stored_at: self.stored_at,
        }
    }
}

impl Inode {
    fn new(kind: Kind, id: u64, created: i64) -> Self {
        Self {
            id,
            kind,
            created,
            modified: created,
            size: 0,
            file_key: Zeroizing::new(random_bytes::<32>()),
            content_blocks: Vec::new(),
            stored_at: u64::MAX,
        }
    }
}

const BLOCK_CACHE_CAP: usize = 32;

struct CachedBlock {
    purpose: u8,
    inode_id: u64,
    logical: u64,
    extra: u32,
    plain: Vec<u8>,
}

impl Drop for CachedBlock {
    fn drop(&mut self) {
        self.plain.zeroize();
    }
}

/// Plaintext of directory and inode blocks. File bodies stay on disk.
struct BlockCache {
    map: HashMap<u64, CachedBlock>,
    order: VecDeque<u64>,
}

impl BlockCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn lookup(
        &mut self,
        physical: u64,
        purpose: u8,
        inode_id: u64,
        logical: u64,
        extra: u32,
    ) -> Option<SecretBuf> {
        let matches = match self.map.get(&physical) {
            None => return None,
            Some(hit) => {
                hit.purpose == purpose
                    && hit.inode_id == inode_id
                    && hit.logical == logical
                    && hit.extra == extra
            }
        };
        if !matches {
            self.forget(physical);
            return None;
        }
        let plain = self.map.get(&physical).unwrap().plain.clone();
        self.touch(physical);
        Some(SecretBuf::new(plain))
    }

    fn remember(
        &mut self,
        physical: u64,
        purpose: u8,
        inode_id: u64,
        logical: u64,
        extra: u32,
        plain: &[u8],
    ) {
        if purpose != PURPOSE_DIR && purpose != PURPOSE_INODE {
            self.forget(physical);
            return;
        }
        self.forget(physical);
        self.map.insert(
            physical,
            CachedBlock {
                purpose,
                inode_id,
                logical,
                extra,
                plain: plain.to_vec(),
            },
        );
        self.order.push_back(physical);
        while self.order.len() > BLOCK_CACHE_CAP {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }

    fn forget(&mut self, physical: u64) {
        self.map.remove(&physical);
        self.order.retain(|block| *block != physical);
    }

    fn touch(&mut self, physical: u64) {
        self.order.retain(|block| *block != physical);
        self.order.push_back(physical);
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

struct StagedReplace {
    inode_id: u64,
    stored_at: u64,
    content_blocks: Vec<u64>,
}

struct PendingPut {
    parent: Vec<String>,
    entry: RawEntry,
    replaced: Option<StagedReplace>,
}

struct Savepoint {
    bitmap: Vec<u8>,
    root: u64,
    next_id: u64,
    used: u64,
    cursor: u64,
    allocated_len: usize,
    freed_len: usize,
    pending_len: usize,
}

struct Txn {
    bitmap_backup: Vec<u8>,
    root_backup: u64,
    next_id_backup: u64,
    used_backup: u64,
    allocated: Vec<u64>,
    freed: Vec<u64>,
    pending: Vec<PendingPut>,
}

pub struct Volume {
    file: File,
    exclusive: bool,
    dek: Box<Zeroizing<[u8; 32]>>,
    kdf: KdfParams,
    salt: [u8; 32],
    volume_id: [u8; 16],
    dek_nonce: [u8; 24],
    wrapped_dek: [u8; 48],
    generation: u64,
    active_super: u8,
    total_physical: u64,
    allocatable_start: u64,
    data_block_count: u64,
    used_blocks: u64,
    next_inode_id: u64,
    root_inode_id: u64,
    root_inode_block: u64,
    created: i64,
    bitmap_slot: u32,
    bitmap_blocks_per_slot: u32,
    bitmap: Vec<u8>,
    alloc_cursor: u64,
    txn: Option<Txn>,
    /// Set once the new superblock is written. Rollback must not run after this.
    commit_durable: bool,
    block_cache: BlockCache,
}

impl Drop for Volume {
    fn drop(&mut self) {
        if self.txn.is_some() {
            if self.commit_durable {
                let _ = self.scrub_freed();
            } else {
                let _ = self.rollback();
            }
        }
        self.block_cache.clear();
        unixutil::munlock_bytes(&self.dek[..]);
        let _ = unixutil::flock_unlock(&self.file);
    }
}

/// True when either superblock copy starts with the HDNFS2 magic.
/// A short or absent header is false. This does not check the password.
pub fn has_volume_magic(path: &Path) -> Result<bool> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    Ok(magic_at(&mut file, 0)? || magic_at(&mut file, SUPER_SIZE as u64)?)
}

fn magic_at(file: &mut File, offset: u64) -> Result<bool> {
    let mut buf = [0u8; 8];
    file.seek(SeekFrom::Start(offset))?;
    match file.read(&mut buf) {
        Ok(8) => Ok(&buf == MAGIC),
        Ok(_) => Ok(false),
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Byte size of a block device, from `BLKGETSIZE64`.
pub fn block_device_bytes(path: &Path) -> Result<u64> {
    let file = OpenOptions::new().read(true).open(path)?;
    if !file.metadata()?.file_type().is_block_device() {
        return Err(Error::Message("not a block device".into()));
    }
    Ok(unixutil::block_device_size(&file)?)
}

pub fn init_volume(opts: InitOptions<'_>) -> Result<u64> {
    crate::password::validate_password(opts.password)?;
    crypto::validate_kdf(&opts.kdf)?;
    let (mut file, device_size, created_new) = prepare(opts.path, opts.size, opts.force)?;
    let result = (|| {
        unixutil::flock_exclusive(&file)?;
        init_locked(
            &mut file,
            opts.password,
            opts.kdf,
            device_size,
            opts.progress,
        )
    })();
    drop(file);
    if result.is_err() && created_new {
        let _ = std::fs::remove_file(opts.path);
    }
    result
}

fn prepare(path: &Path, size: Option<u64>, force: bool) -> Result<(File, u64, bool)> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.file_type().is_block_device() => {
            if !force {
                return Err(Error::Denied(
                    "refusing to initialize a block device without --force".into(),
                ));
            }
            let file = OpenOptions::new().read(true).write(true).open(path)?;
            let device = unixutil::block_device_size(&file)?;
            // A requested size uses only that prefix. The rest of the device is left as it is.
            let span = volume_span(size, device)?;
            Ok((file, span, false))
        }
        Ok(meta) if meta.is_file() => {
            let Some(size) = size else {
                return Err(Error::Message("file volumes require --size".into()));
            };
            if meta.len() > 0 && !force {
                return Err(Error::Denied(
                    "refusing to overwrite a non-empty file without --force".into(),
                ));
            }
            let file = OpenOptions::new().read(true).write(true).open(path)?;
            tighten(path);
            file.set_len(size)?;
            Ok((file, size, false))
        }
        Ok(_) => Err(Error::Message(
            "volume path is not a file or a block device".into(),
        )),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let Some(size) = size else {
                return Err(Error::Message("file volumes require --size".into()));
            };
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            tighten(path);
            file.set_len(size)?;
            Ok((file, size, true))
        }
        Err(err) => Err(err.into()),
    }
}

fn volume_span(requested: Option<u64>, available: u64) -> Result<u64> {
    match requested {
        None => Ok(available),
        Some(size) if size > available => Err(Error::Message(format!(
            "size is {size} bytes but the device is {available} bytes"
        ))),
        Some(size) => Ok(size),
    }
}

fn tighten(path: &Path) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

fn report_progress(
    progress: &mut Option<&mut dyn FnMut(&str, u64, u64) -> Result<()>>,
    stage: &str,
    done: u64,
    total: u64,
    last_pct: &mut u64,
) -> Result<()> {
    let Some(callback) = progress.as_mut() else {
        return Ok(());
    };
    let pct = if total == 0 {
        100
    } else {
        done.saturating_mul(100) / total
    };
    if done != total && pct == *last_pct {
        return Ok(());
    }
    *last_pct = pct;
    callback(stage, done, total)
}

fn init_locked(
    file: &mut File,
    password: &str,
    kdf: KdfParams,
    device_size: u64,
    mut progress: Option<&mut dyn FnMut(&str, u64, u64) -> Result<()>>,
) -> Result<u64> {
    if device_size < 8192 {
        return Err(Error::Message(format!(
            "volume must be at least {} bytes",
            crate::format::minimum_volume_bytes()
        )));
    }
    let total_physical = (device_size - 8192) / BLOCK_SIZE;
    let (blocks_per_slot, allocatable_start, data_blocks) = geometry(total_physical)?;
    // Drop the previous magic before destroying blocks, so a crash cannot
    // leave a superblock that still authenticates and points at wiped data.
    clear_magic(file)?;

    let root_physical = allocatable_start;
    let mut buf = vec![0u8; BLOCK_SIZE as usize];
    let mut last_pct = u64::MAX;
    report_progress(&mut progress, "writing", 0, total_physical, &mut last_pct)?;
    for physical in 0..total_physical {
        if physical >= allocatable_start && physical != root_physical {
            fill_random(&mut buf);
            write_exact_at(file, block_offset(physical), &buf)?;
        }
        report_progress(
            &mut progress,
            "writing",
            physical + 1,
            total_physical,
            &mut last_pct,
        )?;
    }
    let addressable = 8192 + total_physical * BLOCK_SIZE;
    if device_size > addressable {
        let mut left = device_size - addressable;
        let mut offset = addressable;
        while left > 0 {
            let n = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
            fill_random(&mut buf[..n]);
            write_exact_at(file, offset, &buf[..n])?;
            offset += n as u64;
            left -= n as u64;
        }
    }

    report_progress(
        &mut progress,
        "sealing",
        total_physical,
        total_physical,
        &mut last_pct,
    )?;
    let salt = random_bytes::<32>();
    let volume_id = random_bytes::<16>();
    let dek = Zeroizing::new(random_bytes::<32>());
    let kek = derive_kek(password, &salt, &kdf)?;
    let dek_nonce = random_nonce();
    let wrapped_dek = wrap_key(&kek, &dek_nonce, &dek_aad(&volume_id), &dek)?;

    let created = now_unix();
    let root_key_nonce = random_nonce();
    let root_file_key = random_bytes::<32>();
    let wrapped_root = wrap_key(
        &dek,
        &root_key_nonce,
        &file_key_aad(&volume_id, 1),
        &root_file_key,
    )?;
    let record = encode_inode_record(&InodeRecord {
        kind: KIND_DIR,
        inode_id: 1,
        created,
        modified: created,
        size: 0,
        key_nonce: root_key_nonce,
        wrapped_key: wrapped_root,
        blocks: Vec::new(),
    });
    write_record_chain(
        file,
        total_physical,
        &[root_physical],
        &record,
        &dek,
        &volume_id,
        PURPOSE_INODE,
        1,
    )?;

    let mut bitmap = vec![0u8; bitmap_len(data_blocks)];
    bitmap[0] |= 1;
    mask_bitmap(&mut bitmap, data_blocks);
    for slot in 0..2u32 {
        write_bitmap(
            file,
            total_physical,
            &bitmap,
            slot,
            blocks_per_slot,
            &dek,
            &volume_id,
        )?;
    }

    let body = SuperBody {
        generation: 1,
        total_physical,
        allocatable_start,
        data_block_count: data_blocks,
        used_blocks: 1,
        next_inode_id: 2,
        root_inode_id: 1,
        root_inode_block: root_physical,
        created_unix: created,
        bitmap_slot: 0,
        bitmap_blocks_per_slot: blocks_per_slot,
        flags: 0,
    };
    validate_body(&body)?;
    let header_base = SuperHeader {
        kdf_memory_kib: kdf.memory_kib,
        kdf_iterations: kdf.iterations,
        kdf_parallelism: kdf.parallelism,
        salt,
        volume_id,
        dek_nonce,
        wrapped_dek,
        body_nonce: [0u8; 24],
    };
    file.sync_all()?;
    write_super_at(file, 0, &header_base, &body, &dek)?;
    file.sync_all()?;
    write_super_at(file, 1, &header_base, &body, &dek)?;
    file.sync_all()?;
    Ok(addressable)
}

fn clear_magic(file: &mut File) -> Result<()> {
    write_exact_at(file, 0, &[0u8; 8])?;
    write_exact_at(file, 4096, &[0u8; 8])?;
    file.sync_all()?;
    Ok(())
}

impl Volume {
    pub fn open(path: &Path, password: &str, lock: LockMode) -> Result<Self> {
        crate::password::validate_password(password)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        match lock {
            LockMode::Exclusive => unixutil::flock_exclusive(&file)?,
            LockMode::Shared => unixutil::flock_shared(&file)?,
        }
        Self::load(file, password, lock)
    }

    pub fn put(&mut self, src: &Path, dest: &str) -> Result<u64> {
        let parsed = parse_path(dest)?;
        if parsed.components.is_empty() {
            return Err(type_change("/", Kind::Dir));
        }
        let meta = std::fs::metadata(src)
            .map_err(|err| Error::Message(format!("{}: {err}", src.display())))?;
        if !meta.is_file() {
            return Err(Error::Message(format!("{} is not a file", src.display())));
        }
        let parent = parsed.components[..parsed.components.len() - 1].to_vec();
        let name = parsed.components.last().unwrap().clone();
        let full = display_path(&parsed.components);
        self.ensure_parents(&parent)?;
        match self.walk(&parsed.components) {
            Ok(inode) if inode.kind == Kind::Dir => return Err(type_change(&full, Kind::Dir)),
            Ok(_) => {}
            Err(Error::NotFound(_)) => {}
            Err(err) => return Err(err),
        }
        let len = meta.len();
        self.with_txn(|vol| vol.put_txn(src, &parent, &name, len))
    }

    pub fn get(&mut self, src: &str, dest: &Path) -> Result<u64> {
        self.get_with(src, dest, &mut |_, _| Ok(()))
    }

    /// Like `get`, and reports plaintext bytes written. A callback error stops the copy.
    pub fn get_with(
        &mut self,
        src: &str,
        dest: &Path,
        progress: &mut dyn FnMut(u64, u64) -> Result<()>,
    ) -> Result<u64> {
        let parsed = parse_path(src)?;
        if parsed.components.is_empty() {
            return Err(Error::IsDirectory("/".into()));
        }
        let shown = display_path(&parsed.components);
        let inode = self.walk(&parsed.components)?;
        if inode.kind != Kind::File {
            return Err(Error::IsDirectory(shown));
        }
        if let Ok(meta) = std::fs::metadata(dest) {
            if meta.is_dir() {
                return Err(Error::Message(format!("{} is a directory", dest.display())));
            }
        }
        let tmp = partial_path(dest);
        let mut guard = RemoveOnDrop(Some(tmp.clone()));
        let mut output = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        self.stream_to(&inode, &mut output, progress)?;
        output.sync_all()?;
        drop(output);
        std::fs::rename(&tmp, dest)?;
        guard.disarm();
        Ok(inode.size)
    }

    pub fn delete(&mut self, path: &str) -> Result<()> {
        let parsed = parse_path(path)?;
        if parsed.components.is_empty() {
            return Err(Error::Denied("cannot delete the root directory".into()));
        }
        self.with_txn(|vol| vol.delete_txn(&parsed.components))
    }

    pub fn list(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let parsed = parse_path(path)?;
        let shown = display_path(&parsed.components);
        let inode = self.walk(&parsed.components)?;
        if inode.kind != Kind::Dir {
            return Err(Error::NotADirectory(shown));
        }
        let entries = self.read_entries(&inode)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let kind = Kind::from_u8(entry.kind)?;
            out.push(DirEntry {
                name: entry.name,
                size: if kind == Kind::File { entry.size } else { 0 },
                kind,
            });
        }
        Ok(out)
    }

    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        let parsed = parse_path(path)?;
        if parsed.components.is_empty() {
            return Err(Error::AlreadyExists("/".into()));
        }
        let name = parsed.components.last().unwrap().clone();
        let parent = parsed.components[..parsed.components.len() - 1].to_vec();
        match self.walk(&parent) {
            Ok(inode) if inode.kind == Kind::Dir => {}
            Ok(_) => return Err(Error::NotADirectory(display_path(&parent))),
            Err(Error::NotFound(_)) => {
                return Err(Error::NotFound(display_path(&parent)));
            }
            Err(err) => return Err(err),
        }
        self.create_dir(&parent, &name)
    }

    pub fn stat(&mut self, path: Option<&str>) -> Result<Stat> {
        match path {
            None => {
                let free = self.free_blocks();
                Ok(Stat::Volume {
                    size: 8192 + self.total_physical * BLOCK_SIZE,
                    block_size: BLOCK_SIZE,
                    data_blocks: self.data_block_count,
                    used_blocks: self.used_blocks,
                    free_blocks: free,
                    free_payload_bytes: free * PAYLOAD as u64,
                })
            }
            Some(path) => {
                let parsed = parse_path(path)?;
                let inode = self.walk(&parsed.components)?;
                Ok(Stat::Node {
                    path: display_path(&parsed.components),
                    kind: inode.kind,
                    size: inode.size,
                    created: inode.created,
                    modified: inode.modified,
                })
            }
        }
    }

    /// Opens one transaction for a TUI selection. `put` and `mkdir` stay separate.
    pub fn begin_batch(&mut self) -> Result<()> {
        self.begin()
    }

    /// Writes a directory inside the open batch. An existing directory is success.
    pub fn stage_mkdir(&mut self, path: &str) -> Result<()> {
        self.ensure_txn()?;
        let snap = self.snapshot()?;
        match self.mkdir_inside(path) {
            Ok(()) => Ok(()),
            Err(Error::AlreadyExists(existing)) if existing != "/" => Ok(()),
            Err(err) => self.fail_stage(snap, err),
        }
    }

    /// Writes file bytes inside the open batch. The directory entry is published by `finish_batch`.
    pub fn stage_put(&mut self, src: &Path, dest: &str) -> Result<u64> {
        self.ensure_txn()?;
        let snap = self.snapshot()?;
        match self.stage_put_inner(src, dest) {
            Ok(size) => Ok(size),
            Err(err) => self.fail_stage(snap, err),
        }
    }

    /// Publishes staged files. An empty batch changes nothing.
    pub fn finish_batch(&mut self) -> Result<()> {
        if self.txn.is_none() {
            return Ok(());
        }
        let idle = {
            let txn = self.txn.as_ref().unwrap();
            txn.allocated.is_empty() && txn.freed.is_empty() && txn.pending.is_empty()
        };
        if idle {
            return self.rollback();
        }
        if let Err(err) = self.flush_pending() {
            let _ = self.rollback();
            return Err(err);
        }
        self.finish_txn()
    }

    /// Drops the open batch and scrubs blocks it allocated.
    pub fn abort_batch(&mut self) -> Result<()> {
        self.rollback()
    }
}

impl Volume {
    fn load(mut file: File, password: &str, lock: LockMode) -> Result<Self> {
        let raw = [read_super_raw(&mut file, 0)?, read_super_raw(&mut file, 1)?];
        let mut saw_magic = false;
        let mut body_failed = false;
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut kek_cache: Option<(KdfParams, [u8; 32], Zeroizing<[u8; 32]>)> = None;

        for (index, raw) in raw.iter().enumerate() {
            let Some(raw) = raw else { continue };
            let header = match decode_superblock_header(raw) {
                Ok(header) => header,
                Err(Error::NotAVolume) => continue,
                Err(err) => {
                    saw_magic = true;
                    body_failed = true;
                    let _ = err;
                    continue;
                }
            };
            saw_magic = true;
            let kdf = KdfParams {
                memory_kib: header.kdf_memory_kib,
                iterations: header.kdf_iterations,
                parallelism: header.kdf_parallelism,
            };
            if crypto::validate_kdf(&kdf).is_err() {
                body_failed = true;
                continue;
            }
            let kek = match &kek_cache {
                Some((cached_kdf, salt, kek)) if cached_kdf == &kdf && salt == &header.salt => {
                    kek.clone()
                }
                _ => {
                    let kek = match derive_kek(password, &header.salt, &kdf) {
                        Ok(kek) => kek,
                        Err(_) => {
                            body_failed = true;
                            continue;
                        }
                    };
                    kek_cache = Some((kdf, header.salt, kek.clone()));
                    kek
                }
            };
            let dek = match unwrap_key(
                &kek,
                &header.dek_nonce,
                &dek_aad(&header.volume_id),
                &header.wrapped_dek,
            ) {
                Ok(dek) => dek,
                Err(_) => continue,
            };
            let sealed = sealed_body(raw)?;
            let plain = match open(&dek, &header.body_nonce, &sb_aad(&header.volume_id), sealed) {
                Ok(plain) => plain,
                Err(_) => {
                    body_failed = true;
                    continue;
                }
            };
            if plain.len() != BODY_PLAIN_LEN {
                body_failed = true;
                continue;
            }
            let body = match decode_body(&plain) {
                Ok(body) => body,
                Err(_) => {
                    body_failed = true;
                    continue;
                }
            };
            candidates.push(Candidate {
                index,
                header,
                dek,
                body,
                kdf,
            });
        }

        if candidates.is_empty() {
            if !saw_magic {
                return Err(Error::NotAVolume);
            }
            if body_failed {
                return Err(Error::Corrupt("superblock".into()));
            }
            return Err(Error::WrongPassword);
        }
        let generation_of = |index: usize| {
            candidates
                .iter()
                .find(|candidate| candidate.index == index)
                .map(|candidate| candidate.body.generation)
        };
        let winner = prefer_index(generation_of(0), generation_of(1))?;
        let best = candidates
            .into_iter()
            .find(|candidate| candidate.index == winner)
            .ok_or_else(|| Error::Corrupt("superblock".into()))?;
        let dek = Box::new(best.dek);
        unixutil::mlock_bytes(&dek[..]);

        let mut volume = Volume {
            file,
            exclusive: matches!(lock, LockMode::Exclusive),
            dek,
            kdf: best.kdf,
            salt: best.header.salt,
            volume_id: best.header.volume_id,
            dek_nonce: best.header.dek_nonce,
            wrapped_dek: best.header.wrapped_dek,
            generation: best.body.generation,
            active_super: best.index as u8,
            total_physical: best.body.total_physical,
            allocatable_start: best.body.allocatable_start,
            data_block_count: best.body.data_block_count,
            used_blocks: best.body.used_blocks,
            next_inode_id: best.body.next_inode_id,
            root_inode_id: best.body.root_inode_id,
            root_inode_block: best.body.root_inode_block,
            created: best.body.created_unix,
            bitmap_slot: best.body.bitmap_slot,
            bitmap_blocks_per_slot: best.body.bitmap_blocks_per_slot,
            bitmap: Vec::new(),
            alloc_cursor: 0,
            txn: None,
            commit_durable: false,
            block_cache: BlockCache::new(),
        };
        volume.bitmap = volume.read_bitmap()?;
        mask_bitmap(&mut volume.bitmap, volume.data_block_count);
        if volume.bitmap.len() != bitmap_len(volume.data_block_count) {
            return Err(Error::Corrupt("bitmap length".into()));
        }
        if popcount(&volume.bitmap) != volume.used_blocks {
            return Err(Error::Corrupt("used block count".into()));
        }
        let root = volume.load_inode(volume.root_inode_block, volume.root_inode_id)?;
        if root.id != 1 || root.kind != Kind::Dir {
            return Err(Error::Corrupt("root inode".into()));
        }
        Ok(volume)
    }

    fn dek_copy(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.dek[..]);
        out
    }

    fn free_blocks(&self) -> u64 {
        self.data_block_count.saturating_sub(self.used_blocks)
    }

    fn ensure_space(&self, need: u64) -> Result<()> {
        if self.free_blocks() < need {
            Err(Error::Full)
        } else {
            Ok(())
        }
    }

    fn with_txn<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.begin()?;
        match f(self) {
            Ok(value) => self.finish_txn().map(|_| value),
            Err(err) => {
                let _ = self.rollback();
                Err(err)
            }
        }
    }

    fn finish_txn(&mut self) -> Result<()> {
        match self.file.sync_all() {
            Ok(()) => match self.write_commit() {
                Ok(()) => self.scrub_freed(),
                Err(err) if self.commit_durable => {
                    let _ = self.scrub_freed();
                    Err(err)
                }
                Err(err) => {
                    let _ = self.rollback();
                    Err(err)
                }
            },
            Err(err) => {
                let _ = self.rollback();
                Err(err.into())
            }
        }
    }

    fn begin(&mut self) -> Result<()> {
        if !self.exclusive {
            return Err(Error::Denied("volume is open read-only".into()));
        }
        if self.txn.is_some() {
            return Err(Error::Message("nested transaction".into()));
        }
        self.commit_durable = false;
        self.txn = Some(Txn {
            bitmap_backup: self.bitmap.clone(),
            root_backup: self.root_inode_block,
            next_id_backup: self.next_inode_id,
            used_backup: self.used_blocks,
            allocated: Vec::new(),
            freed: Vec::new(),
            pending: Vec::new(),
        });
        Ok(())
    }

    fn ensure_txn(&self) -> Result<()> {
        if self.txn.is_none() {
            Err(Error::Message("no transaction".into()))
        } else {
            Ok(())
        }
    }

    fn snapshot(&mut self) -> Result<Savepoint> {
        let (allocated_len, freed_len, pending_len) = {
            let txn = self
                .txn
                .as_ref()
                .ok_or_else(|| Error::Message("no transaction".into()))?;
            (txn.allocated.len(), txn.freed.len(), txn.pending.len())
        };
        Ok(Savepoint {
            bitmap: self.bitmap.clone(),
            root: self.root_inode_block,
            next_id: self.next_inode_id,
            used: self.used_blocks,
            cursor: self.alloc_cursor,
            allocated_len,
            freed_len,
            pending_len,
        })
    }

    fn fail_stage<T>(&mut self, snap: Savepoint, err: Error) -> Result<T> {
        if let Err(rollback_err) = self.rollback_to(snap) {
            let _ = self.rollback();
            return Err(rollback_err);
        }
        Err(err)
    }

    fn mkdir_inside(&mut self, path: &str) -> Result<()> {
        let parsed = parse_path(path)?;
        if parsed.components.is_empty() {
            return Err(Error::AlreadyExists("/".into()));
        }
        let name = parsed.components.last().unwrap().clone();
        let parent = parsed.components[..parsed.components.len() - 1].to_vec();
        self.create_dir_txn(&parent, &name)
    }

    fn stage_put_inner(&mut self, src: &Path, dest: &str) -> Result<u64> {
        let parsed = parse_path(dest)?;
        if parsed.components.is_empty() {
            return Err(type_change("/", Kind::Dir));
        }
        let meta = std::fs::metadata(src)
            .map_err(|err| Error::Message(format!("{}: {err}", src.display())))?;
        if !meta.is_file() {
            return Err(Error::Message(format!("{} is not a file", src.display())));
        }
        let parent = parsed.components[..parsed.components.len() - 1].to_vec();
        let name = parsed.components.last().unwrap().clone();
        let shown = display_path(&parsed.components);
        let parent_inode = self.walk(&parent)?;
        if parent_inode.kind != Kind::Dir {
            return Err(Error::NotADirectory(display_path(&parent)));
        }
        if self.pending_has(&parent, &name) {
            return Err(Error::Message(format!(
                "{shown} is already included in this copy"
            )));
        }
        let entries = self.read_entries(&parent_inode)?;
        let (created, replaced) = match entries
            .binary_search_by(|entry| entry.name.as_str().cmp(name.as_str()))
        {
            Ok(index) => {
                if Kind::from_u8(entries[index].kind)? != Kind::File {
                    return Err(type_change(&shown, Kind::Dir));
                }
                let old = self.load_inode(entries[index].inode_block, entries[index].inode_id)?;
                (
                    old.created,
                    Some(StagedReplace {
                        inode_id: old.id,
                        stored_at: old.stored_at,
                        content_blocks: old.content_blocks.clone(),
                    }),
                )
            }
            Err(_) => (now_unix(), None),
        };
        let file_blocks = div_ceil(meta.len(), PAYLOAD as u64);
        self.ensure_space(blocks_for(file_blocks))?;
        let id = self.alloc_inode_id();
        let mut file_inode = Inode::new(Kind::File, id, created);
        self.write_file_stream(&mut file_inode, src)?;
        let file_block = self.store_inode(&file_inode)?;
        self.txn
            .as_mut()
            .ok_or_else(|| Error::Message("no transaction".into()))?
            .pending
            .push(PendingPut {
                parent,
                entry: RawEntry {
                    name,
                    inode_id: id,
                    kind: KIND_FILE,
                    inode_block: file_block,
                    size: file_inode.size,
                },
                replaced,
            });
        Ok(file_inode.size)
    }

    fn pending_has(&self, parent: &[String], name: &str) -> bool {
        self.txn.as_ref().is_some_and(|txn| {
            txn.pending
                .iter()
                .any(|item| item.parent == parent && item.entry.name == name)
        })
    }

    fn flush_pending(&mut self) -> Result<()> {
        let pending = {
            let txn = self
                .txn
                .as_mut()
                .ok_or_else(|| Error::Message("no transaction".into()))?;
            std::mem::take(&mut txn.pending)
        };
        if pending.is_empty() {
            return Ok(());
        }
        let mut groups: BTreeMap<Vec<String>, Vec<PendingPut>> = BTreeMap::new();
        for item in pending {
            groups.entry(item.parent.clone()).or_default().push(item);
        }
        for (parent, items) in groups {
            self.flush_group(&parent, items)?;
        }
        Ok(())
    }

    fn flush_group(&mut self, parent_comps: &[String], items: Vec<PendingPut>) -> Result<()> {
        let parent = self.walk(parent_comps)?;
        if parent.kind != Kind::Dir {
            return Err(Error::NotADirectory(display_path(parent_comps)));
        }
        let mut entries = self.read_entries(&parent)?;
        let mut replaced = Vec::new();
        for item in items {
            let name = item.entry.name.clone();
            match entries.binary_search_by(|entry| entry.name.as_str().cmp(name.as_str())) {
                Ok(index) => {
                    if Kind::from_u8(entries[index].kind)? != Kind::File {
                        let mut parts = parent_comps.to_vec();
                        parts.push(name);
                        return Err(type_change(&display_path(&parts), Kind::Dir));
                    }
                    entries[index] = item.entry;
                }
                Err(index) => entries.insert(index, item.entry),
            }
            if let Some(old) = item.replaced {
                replaced.push(old);
            }
        }
        self.save_dir(parent_comps, parent, entries)?;
        for old in replaced {
            for block in old.content_blocks {
                self.free_block(block)?;
            }
            self.free_inode_chain(old.stored_at, old.inode_id)?;
        }
        Ok(())
    }

    fn write_commit(&mut self) -> Result<()> {
        let (allocated, freed) = {
            let txn = self
                .txn
                .as_ref()
                .ok_or_else(|| Error::Message("no transaction".into()))?;
            (txn.allocated.clone(), txn.freed.clone())
        };
        // A batch rewrites directories it created earlier in this same transaction.
        // Those blocks are in both lists and are clear in the bitmap, then scrubbed.
        // A block that is still marked used must not be both.
        for block in &freed {
            if allocated.contains(block) {
                let index = block - self.allocatable_start;
                if self.bit(index) {
                    return Err(Error::Corrupt("block both allocated and freed".into()));
                }
            }
        }
        if popcount(&self.bitmap) != self.used_blocks {
            return Err(Error::Corrupt("used block count mismatch".into()));
        }
        let new_slot = 1 - self.bitmap_slot;
        let new_gen = self
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::Corrupt("generation overflow".into()))?;
        let inactive = 1 - self.active_super;
        self.write_bitmap_slot(new_slot)?;
        self.file.sync_all()?;
        self.write_super_copy(inactive, new_gen, new_slot)?;
        self.commit_durable = true;
        self.generation = new_gen;
        self.bitmap_slot = new_slot;
        self.active_super = inactive;
        self.file.sync_all()?;
        Ok(())
    }

    fn scrub_freed(&mut self) -> Result<()> {
        let Some(txn) = self.txn.take() else {
            return Ok(());
        };
        let mut first = None;
        for block in txn.freed {
            if let Err(err) = self.scrub_block(block) {
                if first.is_none() {
                    first = Some(err);
                }
            }
        }
        if let Err(err) = self.file.sync_all() {
            if first.is_none() {
                first = Some(err.into());
            }
        }
        match first {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn rollback(&mut self) -> Result<()> {
        if self.commit_durable {
            return Ok(());
        }
        let Some(txn) = self.txn.take() else {
            return Ok(());
        };
        self.bitmap = txn.bitmap_backup;
        self.root_inode_block = txn.root_backup;
        self.next_inode_id = txn.next_id_backup;
        self.used_blocks = txn.used_backup;
        for block in txn.allocated {
            let _ = self.scrub_block(block);
        }
        let _ = self.file.sync_all();
        self.block_cache.clear();
        Ok(())
    }

    fn rollback_to(&mut self, snap: Savepoint) -> Result<()> {
        if self.commit_durable {
            return Err(Error::Message("transaction is already durable".into()));
        }
        let extra = {
            let txn = self
                .txn
                .as_mut()
                .ok_or_else(|| Error::Message("no transaction".into()))?;
            if snap.allocated_len > txn.allocated.len()
                || snap.freed_len > txn.freed.len()
                || snap.pending_len > txn.pending.len()
            {
                return Err(Error::Corrupt(
                    "savepoint is ahead of the transaction".into(),
                ));
            }
            txn.freed.truncate(snap.freed_len);
            txn.pending.truncate(snap.pending_len);
            txn.allocated.split_off(snap.allocated_len)
        };
        self.bitmap = snap.bitmap;
        self.root_inode_block = snap.root;
        self.next_inode_id = snap.next_id;
        self.used_blocks = snap.used;
        self.alloc_cursor = snap.cursor;
        let mut first = None;
        for block in extra {
            if let Err(err) = self.scrub_block(block) {
                if first.is_none() {
                    first = Some(err);
                }
            }
        }
        if let Err(err) = self.file.sync_all() {
            if first.is_none() {
                first = Some(err.into());
            }
        }
        self.block_cache.clear();
        match first {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn bit(&self, index: u64) -> bool {
        let index = index as usize;
        self.bitmap[index / 8] & (1 << (index % 8)) != 0
    }

    fn set_bit(&mut self, index: u64, value: bool) {
        let index = index as usize;
        let byte = &mut self.bitmap[index / 8];
        if value {
            *byte |= 1 << (index % 8);
        } else {
            *byte &= !(1 << (index % 8));
        }
    }

    fn alloc_block(&mut self) -> Result<u64> {
        let freed = self
            .txn
            .as_ref()
            .ok_or_else(|| Error::Message("no transaction".into()))?
            .freed
            .clone();
        let count = self.data_block_count;
        if count == 0 {
            return Err(Error::Full);
        }
        let start = self.alloc_cursor % count;
        for step in 0..count {
            let index = (start + step) % count;
            let physical = self.allocatable_start + index;
            if freed.contains(&physical) || self.bit(index) {
                continue;
            }
            self.set_bit(index, true);
            self.used_blocks += 1;
            self.alloc_cursor = (index + 1) % count;
            self.txn.as_mut().unwrap().allocated.push(physical);
            self.block_cache.forget(physical);
            return Ok(physical);
        }
        Err(Error::Full)
    }

    fn free_block(&mut self, physical: u64) -> Result<()> {
        self.check_data_block(physical)?;
        let index = physical - self.allocatable_start;
        if !self.bit(index) {
            return Err(Error::Corrupt(format!("double free of block {physical}")));
        }
        self.set_bit(index, false);
        self.used_blocks -= 1;
        self.txn
            .as_mut()
            .ok_or_else(|| Error::Message("no transaction".into()))?
            .freed
            .push(physical);
        self.block_cache.forget(physical);
        Ok(())
    }

    fn alloc_inode_id(&mut self) -> u64 {
        let id = self.next_inode_id;
        self.next_inode_id += 1;
        id
    }

    fn check_data_block(&self, physical: u64) -> Result<()> {
        if physical < self.allocatable_start
            || physical >= self.allocatable_start + self.data_block_count
        {
            Err(Error::Corrupt(format!("bad data block {physical}")))
        } else {
            Ok(())
        }
    }

    fn read_sealed(
        &mut self,
        physical: u64,
        key: &[u8; 32],
        purpose: u8,
        inode_id: u64,
        logical: u64,
        extra: u32,
    ) -> Result<SecretBuf> {
        // File bodies are not cached. They are large, and a read must see the device.
        if purpose == PURPOSE_DIR || purpose == PURPOSE_INODE {
            if let Some(cached) = self
                .block_cache
                .lookup(physical, purpose, inode_id, logical, extra)
            {
                return Ok(cached);
            }
        }
        let volume_id = self.volume_id;
        let total = self.total_physical;
        let plain = read_sealed_at(
            &mut self.file,
            total,
            physical,
            key,
            &volume_id,
            purpose,
            inode_id,
            logical,
            extra,
        )?;
        if purpose == PURPOSE_DIR || purpose == PURPOSE_INODE {
            self.block_cache
                .remember(physical, purpose, inode_id, logical, extra, &plain);
        }
        Ok(plain)
    }

    fn write_sealed(
        &mut self,
        physical: u64,
        plain: &[u8],
        key: &[u8; 32],
        purpose: u8,
        inode_id: u64,
        logical: u64,
        extra: u32,
    ) -> Result<()> {
        let volume_id = self.volume_id;
        let total = self.total_physical;
        write_sealed_at(
            &mut self.file,
            total,
            physical,
            plain,
            key,
            &volume_id,
            purpose,
            inode_id,
            logical,
            extra,
        )?;
        if purpose == PURPOSE_DIR || purpose == PURPOSE_INODE {
            self.block_cache
                .remember(physical, purpose, inode_id, logical, extra, plain);
        } else {
            self.block_cache.forget(physical);
        }
        Ok(())
    }

    fn scrub_block(&mut self, physical: u64) -> Result<()> {
        self.block_cache.forget(physical);
        self.check_data_block(physical)?;
        let mut buf = vec![0u8; BLOCK_SIZE as usize];
        fill_random(&mut buf);
        write_exact_at(&mut self.file, block_offset(physical), &buf)?;
        buf.zeroize();
        Ok(())
    }

    fn read_bitmap(&mut self) -> Result<Vec<u8>> {
        let blen = bitmap_len(self.data_block_count);
        let mut bitmap = vec![0u8; blen];
        let dek = self.dek_copy();
        let blocks = u64::from(self.bitmap_blocks_per_slot);
        let start = u64::from(self.bitmap_slot) * blocks;
        for index in 0..blocks {
            let plain = self.read_sealed(
                start + index,
                &dek,
                PURPOSE_BITMAP,
                0,
                index,
                self.bitmap_slot,
            )?;
            let offset = index as usize * PAYLOAD;
            if offset >= blen {
                if plain.iter().any(|byte| *byte != 0) {
                    return Err(Error::Corrupt("bitmap padding".into()));
                }
                continue;
            }
            let end = (offset + PAYLOAD).min(blen);
            let n = end - offset;
            bitmap[offset..end].copy_from_slice(&plain[..n]);
            if plain[n..].iter().any(|byte| *byte != 0) {
                return Err(Error::Corrupt("bitmap padding".into()));
            }
        }
        Ok(bitmap)
    }

    fn write_bitmap_slot(&mut self, slot: u32) -> Result<()> {
        let dek = self.dek_copy();
        let volume_id = self.volume_id;
        let total = self.total_physical;
        write_bitmap(
            &mut self.file,
            total,
            &self.bitmap,
            slot,
            self.bitmap_blocks_per_slot,
            &dek,
            &volume_id,
        )
    }

    fn write_super_copy(&mut self, index: u8, generation: u64, bitmap_slot: u32) -> Result<()> {
        let body = SuperBody {
            generation,
            total_physical: self.total_physical,
            allocatable_start: self.allocatable_start,
            data_block_count: self.data_block_count,
            used_blocks: self.used_blocks,
            next_inode_id: self.next_inode_id,
            root_inode_id: self.root_inode_id,
            root_inode_block: self.root_inode_block,
            created_unix: self.created,
            bitmap_slot,
            bitmap_blocks_per_slot: self.bitmap_blocks_per_slot,
            flags: 0,
        };
        let header = SuperHeader {
            kdf_memory_kib: self.kdf.memory_kib,
            kdf_iterations: self.kdf.iterations,
            kdf_parallelism: self.kdf.parallelism,
            salt: self.salt,
            volume_id: self.volume_id,
            dek_nonce: self.dek_nonce,
            wrapped_dek: self.wrapped_dek,
            body_nonce: [0u8; 24],
        };
        let dek = self.dek_copy();
        write_super_at(&mut self.file, index, &header, &body, &dek)
    }

    fn load_inode(&mut self, block: u64, expected_id: u64) -> Result<Inode> {
        let record_bytes = self.read_inode_record(block, expected_id)?;
        let record = decode_inode_record(&record_bytes)?;
        if record.inode_id != expected_id {
            return Err(Error::Corrupt("inode id mismatch".into()));
        }
        let expect = div_ceil(record.size, PAYLOAD as u64);
        if record.blocks.len() as u64 != expect {
            return Err(Error::Corrupt(
                "inode size does not match its block list".into(),
            ));
        }
        for physical in &record.blocks {
            self.check_data_block(*physical)?;
        }
        let dek = self.dek_copy();
        let file_key = unwrap_key(
            &dek,
            &record.key_nonce,
            &file_key_aad(&self.volume_id, expected_id),
            &record.wrapped_key,
        )
        .map_err(|_| Error::Corrupt("file key".into()))?;
        Ok(Inode {
            id: record.inode_id,
            kind: Kind::from_u8(record.kind)?,
            created: record.created,
            modified: record.modified,
            size: record.size,
            file_key,
            content_blocks: record.blocks,
            stored_at: block,
        })
    }

    fn read_inode_record(&mut self, first: u64, inode_id: u64) -> Result<Vec<u8>> {
        let dek = self.dek_copy();
        let mut out = Vec::new();
        let mut block = first;
        let mut seen = Vec::new();
        loop {
            if seen.contains(&block) || seen.len() > 1024 {
                return Err(Error::Corrupt("inode chain".into()));
            }
            seen.push(block);
            self.check_data_block(block)?;
            let plain = self.read_sealed(
                block,
                &dek,
                PURPOSE_INODE,
                inode_id,
                seen.len() as u64 - 1,
                0,
            )?;
            let (next, chunk) = split_chain(&plain)?;
            out.extend_from_slice(chunk);
            if next == CHAIN_END {
                break;
            }
            block = next;
        }
        Ok(out)
    }

    fn store_inode(&mut self, inode: &Inode) -> Result<u64> {
        let dek = self.dek_copy();
        let volume_id = self.volume_id;
        let total = self.total_physical;
        let record = seal_inode(inode, &volume_id, &dek)?;
        let cap = PAYLOAD - 12;
        let count = record.len().div_ceil(cap).max(1);
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            blocks.push(self.alloc_block()?);
        }
        write_record_chain(
            &mut self.file,
            total,
            &blocks,
            &record,
            &dek,
            &volume_id,
            PURPOSE_INODE,
            inode.id,
        )?;
        Ok(blocks[0])
    }

    fn free_inode_chain(&mut self, first: u64, inode_id: u64) -> Result<()> {
        if first == u64::MAX {
            return Err(Error::Corrupt("inode was never stored".into()));
        }
        let dek = self.dek_copy();
        let mut block = first;
        let mut seen = Vec::new();
        loop {
            if seen.contains(&block) || seen.len() > 1024 {
                return Err(Error::Corrupt("inode chain".into()));
            }
            seen.push(block);
            self.check_data_block(block)?;
            let logical = seen.len() as u64 - 1;
            let plain = self.read_sealed(block, &dek, PURPOSE_INODE, inode_id, logical, 0)?;
            let (next, _) = split_chain(&plain)?;
            self.free_block(block)?;
            if next == CHAIN_END {
                break;
            }
            block = next;
        }
        Ok(())
    }

    fn read_entries(&mut self, inode: &Inode) -> Result<Vec<RawEntry>> {
        if inode.kind != Kind::Dir {
            return Err(Error::NotADirectory(format!("inode {}", inode.id)));
        }
        if inode.size > MAX_DIR_BYTES {
            return Err(Error::Corrupt("directory too large".into()));
        }
        let data = self.read_logical(inode, PURPOSE_DIR)?;
        decode_entries(&data)
    }

    fn read_logical(&mut self, inode: &Inode, purpose: u8) -> Result<SecretBuf> {
        let expect = div_ceil(inode.size, PAYLOAD as u64);
        if inode.content_blocks.len() as u64 != expect {
            return Err(Error::Corrupt("block count mismatch".into()));
        }
        if inode.size == 0 {
            return Ok(SecretBuf::new(Vec::new()));
        }
        let mut out = vec![0u8; inode.size as usize];
        let key = inode.file_key.clone();
        let mut offset = 0usize;
        for (index, block) in inode.content_blocks.iter().enumerate() {
            let plain = self.read_sealed(*block, &key, purpose, inode.id, index as u64, 0)?;
            let take = (out.len() - offset).min(PAYLOAD);
            if index + 1 == inode.content_blocks.len()
                && plain[take..].iter().any(|byte| *byte != 0)
            {
                return Err(Error::Corrupt("content padding".into()));
            }
            out[offset..offset + take].copy_from_slice(&plain[..take]);
            offset += take;
        }
        if offset != out.len() {
            return Err(Error::Corrupt("short object".into()));
        }
        Ok(SecretBuf::new(out))
    }

    fn write_content(&mut self, inode: &mut Inode, data: &[u8], purpose: u8) -> Result<()> {
        if purpose == PURPOSE_DIR && data.len() as u64 > MAX_DIR_BYTES {
            return Err(Error::Message("directory too large".into()));
        }
        let old = std::mem::take(&mut inode.content_blocks);
        for block in old {
            self.free_block(block)?;
        }
        if data.is_empty() {
            inode.size = 0;
            inode.modified = now_unix();
            return Ok(());
        }
        let key = inode.file_key.clone();
        let id = inode.id;
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + PAYLOAD).min(data.len());
            let mut plain = vec![0u8; PAYLOAD];
            plain[..end - offset].copy_from_slice(&data[offset..end]);
            let physical = self.alloc_block()?;
            let logical = inode.content_blocks.len() as u64;
            self.write_sealed(physical, &plain, &key, purpose, id, logical, 0)?;
            plain.zeroize();
            inode.content_blocks.push(physical);
            offset = end;
        }
        inode.size = data.len() as u64;
        inode.modified = now_unix();
        Ok(())
    }

    fn stream_to(
        &mut self,
        inode: &Inode,
        out: &mut impl Write,
        progress: &mut dyn FnMut(u64, u64) -> Result<()>,
    ) -> Result<()> {
        let expect = div_ceil(inode.size, PAYLOAD as u64);
        if inode.content_blocks.len() as u64 != expect {
            return Err(Error::Corrupt("block count mismatch".into()));
        }
        let key = inode.file_key.clone();
        let mut remaining = inode.size;
        let mut written = 0u64;
        progress(0, inode.size)?;
        for (index, block) in inode.content_blocks.iter().enumerate() {
            let plain = self.read_sealed(*block, &key, PURPOSE_FILE, inode.id, index as u64, 0)?;
            let take = usize::try_from(remaining.min(PAYLOAD as u64)).unwrap_or(PAYLOAD);
            if index + 1 == inode.content_blocks.len()
                && plain[take..].iter().any(|byte| *byte != 0)
            {
                return Err(Error::Corrupt("content padding".into()));
            }
            out.write_all(&plain[..take])?;
            written += take as u64;
            remaining -= take as u64;
            progress(written, inode.size)?;
        }
        if remaining != 0 {
            return Err(Error::Corrupt("short file".into()));
        }
        Ok(())
    }

    fn write_file_stream(&mut self, inode: &mut Inode, src: &Path) -> Result<()> {
        let mut input = File::open(src)?;
        let key = inode.file_key.clone();
        let id = inode.id;
        let mut buf = vec![0u8; PAYLOAD];
        let mut total = 0u64;
        loop {
            let n = read_chunk(&mut input, &mut buf)?;
            if n == 0 {
                break;
            }
            if n < PAYLOAD {
                buf[n..].fill(0);
            }
            let physical = self.alloc_block()?;
            let logical = inode.content_blocks.len() as u64;
            self.write_sealed(physical, &buf, &key, PURPOSE_FILE, id, logical, 0)?;
            inode.content_blocks.push(physical);
            total += n as u64;
            if n < PAYLOAD {
                break;
            }
        }
        buf.zeroize();
        inode.size = total;
        inode.modified = now_unix();
        Ok(())
    }

    fn collect_inodes(&mut self, comps: &[String]) -> Result<Vec<Inode>> {
        let mut out = Vec::new();
        let root = self.load_inode(self.root_inode_block, self.root_inode_id)?;
        out.push(root);
        for (depth, name) in comps.iter().enumerate() {
            let parent = out.last().unwrap().clone();
            if parent.kind != Kind::Dir {
                return Err(Error::NotADirectory(display_path(&comps[..depth])));
            }
            let entries = self.read_entries(&parent)?;
            match entries.binary_search_by(|entry| entry.name.as_str().cmp(name.as_str())) {
                Ok(index) => {
                    let entry = &entries[index];
                    let child = self.load_inode(entry.inode_block, entry.inode_id)?;
                    if child.kind.as_u8() != entry.kind {
                        return Err(Error::Corrupt(format!("kind mismatch at {name}")));
                    }
                    out.push(child);
                }
                Err(_) => return Err(Error::NotFound(display_path(&comps[..=depth]))),
            }
        }
        Ok(out)
    }

    fn walk(&mut self, comps: &[String]) -> Result<Inode> {
        let mut chain = self.collect_inodes(comps)?;
        chain
            .pop()
            .ok_or_else(|| Error::Corrupt("empty walk".into()))
    }

    fn save_dir(&mut self, comps: &[String], mut dir: Inode, entries: Vec<RawEntry>) -> Result<()> {
        let blob = encode_entries(&entries)?;
        self.write_content(&mut dir, &blob, PURPOSE_DIR)?;
        let old = dir.stored_at;
        let new_block = self.store_inode(&dir)?;
        self.free_inode_chain(old, dir.id)?;
        if comps.is_empty() {
            self.root_inode_block = new_block;
            return Ok(());
        }
        let parent_comps = &comps[..comps.len() - 1];
        let name = comps[comps.len() - 1].clone();
        let parent = self.walk(parent_comps)?;
        let mut parent_entries = self.read_entries(&parent)?;
        match parent_entries.iter_mut().find(|entry| entry.name == name) {
            Some(entry) => {
                entry.inode_block = new_block;
                entry.inode_id = dir.id;
                entry.kind = dir.kind.as_u8();
                entry.size = if dir.kind == Kind::File { dir.size } else { 0 };
            }
            None => {
                return Err(Error::Corrupt(format!("missing directory entry {name}")));
            }
        }
        self.save_dir(parent_comps, parent, parent_entries)
    }

    fn ensure_parents(&mut self, comps: &[String]) -> Result<()> {
        for index in 0..comps.len() {
            match self.walk(&comps[..=index]) {
                Ok(inode) => {
                    if inode.kind != Kind::Dir {
                        return Err(Error::NotADirectory(display_path(&comps[..=index])));
                    }
                }
                Err(Error::NotFound(_)) => {
                    self.create_dir(&comps[..index], &comps[index])?;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn create_dir(&mut self, parent_comps: &[String], name: &str) -> Result<()> {
        let parent_owned = parent_comps.to_vec();
        let name_owned = name.to_string();
        self.with_txn(|vol| vol.create_dir_txn(&parent_owned, &name_owned))
    }

    fn create_dir_txn(&mut self, parent_comps: &[String], name: &str) -> Result<()> {
        let chain = self.collect_inodes(parent_comps)?;
        let parent = chain.last().unwrap().clone();
        if parent.kind != Kind::Dir {
            return Err(Error::NotADirectory(display_path(parent_comps)));
        }
        let mut entries = self.read_entries(&parent)?;
        let mut full = parent_comps.to_vec();
        full.push(name.to_string());
        let shown = display_path(&full);
        if let Ok(index) = entries.binary_search_by(|entry| entry.name.as_str().cmp(name)) {
            let kind = Kind::from_u8(entries[index].kind)?;
            if kind == Kind::Dir {
                return Err(Error::AlreadyExists(shown));
            }
            return Err(type_change(&shown, Kind::File));
        }
        let mut tentative = entries.clone();
        let insert_at = tentative
            .binary_search_by(|entry| entry.name.as_str().cmp(name))
            .unwrap_err();
        tentative.insert(
            insert_at,
            RawEntry {
                name: name.to_string(),
                inode_id: 1,
                kind: KIND_DIR,
                inode_block: self.allocatable_start,
                size: 0,
            },
        );
        let parent_bytes = encode_entries(&tentative)?.len() as u64;
        let mut need = 1u64;
        need += blocks_for(div_ceil(parent_bytes, PAYLOAD as u64));
        for inode in &chain[..chain.len() - 1] {
            need += blocks_for(div_ceil(inode.size, PAYLOAD as u64));
        }
        self.ensure_space(need)?;
        let id = self.alloc_inode_id();
        let child = Inode::new(Kind::Dir, id, now_unix());
        let child_block = self.store_inode(&child)?;
        let insert_at = entries
            .binary_search_by(|entry| entry.name.as_str().cmp(name))
            .unwrap_err();
        entries.insert(
            insert_at,
            RawEntry {
                name: name.to_string(),
                inode_id: id,
                kind: KIND_DIR,
                inode_block: child_block,
                size: 0,
            },
        );
        self.save_dir(parent_comps, parent, entries)
    }

    fn put_txn(
        &mut self,
        src: &Path,
        parent_comps: &[String],
        name: &str,
        file_len: u64,
    ) -> Result<u64> {
        let parent = self.walk(parent_comps)?;
        if parent.kind != Kind::Dir {
            return Err(Error::NotADirectory(display_path(parent_comps)));
        }
        let mut entries = self.read_entries(&parent)?;
        let mut shown_parts = parent_comps.to_vec();
        shown_parts.push(name.to_string());
        let shown = display_path(&shown_parts);
        let now = now_unix();
        let (created, old) = match entries.binary_search_by(|entry| entry.name.as_str().cmp(name)) {
            Ok(index) => {
                if Kind::from_u8(entries[index].kind)? != Kind::File {
                    return Err(type_change(&shown, Kind::Dir));
                }
                let old = self.load_inode(entries[index].inode_block, entries[index].inode_id)?;
                (old.created, Some(old))
            }
            Err(_) => (now, None),
        };
        let file_blocks = div_ceil(file_len, PAYLOAD as u64);
        let mut need = blocks_for(file_blocks);
        let mut tentative = entries.clone();
        let placeholder = RawEntry {
            name: name.to_string(),
            inode_id: 1,
            kind: KIND_FILE,
            inode_block: self.allocatable_start,
            size: file_len,
        };
        match tentative.binary_search_by(|entry| entry.name.as_str().cmp(name)) {
            Ok(index) => tentative[index] = placeholder,
            Err(index) => tentative.insert(index, placeholder),
        }
        let parent_bytes = encode_entries(&tentative)?.len() as u64;
        need += blocks_for(div_ceil(parent_bytes, PAYLOAD as u64));
        if !parent_comps.is_empty() {
            let above = self.collect_inodes(&parent_comps[..parent_comps.len() - 1])?;
            for inode in &above {
                need += blocks_for(div_ceil(inode.size, PAYLOAD as u64));
            }
        }
        self.ensure_space(need)?;

        let id = self.alloc_inode_id();
        let mut file_inode = Inode::new(Kind::File, id, created);
        self.write_file_stream(&mut file_inode, src)?;
        let file_block = self.store_inode(&file_inode)?;
        let entry = RawEntry {
            name: name.to_string(),
            inode_id: id,
            kind: KIND_FILE,
            inode_block: file_block,
            size: file_inode.size,
        };
        match entries.binary_search_by(|entry| entry.name.as_str().cmp(name)) {
            Ok(index) => entries[index] = entry,
            Err(index) => entries.insert(index, entry),
        }
        self.save_dir(parent_comps, parent, entries)?;
        if let Some(old) = old {
            self.free_content(&old)?;
            self.free_inode_chain(old.stored_at, old.id)?;
        }
        Ok(file_inode.size)
    }

    fn free_content(&mut self, inode: &Inode) -> Result<()> {
        for block in &inode.content_blocks {
            self.free_block(*block)?;
        }
        Ok(())
    }

    fn delete_txn(&mut self, comps: &[String]) -> Result<()> {
        let parent_comps = &comps[..comps.len() - 1];
        let name = comps.last().unwrap();
        let chain = self.collect_inodes(parent_comps)?;
        let parent = chain.last().unwrap().clone();
        if parent.kind != Kind::Dir {
            return Err(Error::NotADirectory(display_path(parent_comps)));
        }
        let mut entries = self.read_entries(&parent)?;
        let index = entries
            .binary_search_by(|entry| entry.name.as_str().cmp(name.as_str()))
            .map_err(|_| Error::NotFound(display_path(comps)))?;
        let child = self.load_inode(entries[index].inode_block, entries[index].inode_id)?;
        if child.kind == Kind::Dir {
            let kids = self.read_entries(&child)?;
            if !kids.is_empty() {
                return Err(Error::NotEmpty(display_path(comps)));
            }
        }
        let mut need = 0u64;
        for inode in &chain {
            need += blocks_for(div_ceil(inode.size, PAYLOAD as u64));
        }
        self.ensure_space(need)?;
        entries.remove(index);
        self.free_content(&child)?;
        self.free_inode_chain(child.stored_at, child.id)?;
        self.save_dir(parent_comps, parent, entries)
    }
}

struct Candidate {
    index: usize,
    header: SuperHeader,
    dek: Zeroizing<[u8; 32]>,
    body: SuperBody,
    kdf: KdfParams,
}

fn blocks_for(content_blocks: u64) -> u64 {
    content_blocks + inode_chain_blocks(content_blocks)
}

fn type_change(path: &str, existing: Kind) -> Error {
    let (existing, target) = match existing {
        Kind::Dir => ("directory", "file"),
        Kind::File => ("file", "directory"),
    };
    Error::TypeImmutable {
        path: path.to_string(),
        existing: existing.into(),
        target: target.into(),
    }
}

fn seal_inode(inode: &Inode, volume_id: &[u8; 16], dek: &[u8; 32]) -> Result<Vec<u8>> {
    let nonce = random_nonce();
    let wrapped = wrap_key(
        dek,
        &nonce,
        &file_key_aad(volume_id, inode.id),
        &inode.file_key,
    )?;
    Ok(encode_inode_record(&InodeRecord {
        kind: inode.kind.as_u8(),
        inode_id: inode.id,
        created: inode.created,
        modified: inode.modified,
        size: inode.size,
        key_nonce: nonce,
        wrapped_key: wrapped,
        blocks: inode.content_blocks.clone(),
    }))
}

fn split_chain(plain: &[u8]) -> Result<(u64, &[u8])> {
    if plain.len() < 12 {
        return Err(Error::Corrupt("short inode block".into()));
    }
    let next = u64::from_le_bytes(plain[0..8].try_into().unwrap());
    let len = u32::from_le_bytes(plain[8..12].try_into().unwrap()) as usize;
    if len > PAYLOAD - 12 || 12 + len > plain.len() {
        return Err(Error::Corrupt("bad inode chunk length".into()));
    }
    if plain[12 + len..].iter().any(|byte| *byte != 0) {
        return Err(Error::Corrupt("inode padding".into()));
    }
    Ok((next, &plain[12..12 + len]))
}

fn read_chunk(file: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(filled)
}

fn partial_path(dest: &Path) -> PathBuf {
    let mut name = dest
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("hdnfs-out"));
    let n = u32::from_le_bytes(random_bytes::<4>());
    name.push(format!(".hdnfs-partial-{n}"));
    dest.with_file_name(name)
}

struct RemoveOnDrop(Option<PathBuf>);

impl RemoveOnDrop {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn popcount(bitmap: &[u8]) -> u64 {
    bitmap.iter().map(|byte| u64::from(byte.count_ones())).sum()
}

fn read_super_raw(file: &mut File, index: usize) -> Result<Option<[u8; SUPER_SIZE]>> {
    let mut buf = [0u8; SUPER_SIZE];
    match read_exact_at(file, (index * SUPER_SIZE) as u64, &mut buf) {
        Err(Error::Io(err)) if err.kind() == ErrorKind::UnexpectedEof => Ok(None),
        Err(err) => Err(err),
        Ok(()) => Ok(Some(buf)),
    }
}

fn read_exact_at(file: &mut File, offset: u64, buf: &mut [u8]) -> Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)?;
    Ok(())
}

fn write_exact_at(file: &mut File, offset: u64, buf: &[u8]) -> Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(buf)?;
    Ok(())
}

fn write_sealed_at(
    file: &mut File,
    total_physical: u64,
    physical: u64,
    plain: &[u8],
    key: &[u8; 32],
    volume_id: &[u8; 16],
    purpose: u8,
    inode_id: u64,
    logical: u64,
    extra: u32,
) -> Result<()> {
    if physical >= total_physical {
        return Err(Error::Corrupt(format!("block {physical} out of range")));
    }
    if plain.len() != PAYLOAD {
        return Err(Error::Corrupt("plaintext is not a full block".into()));
    }
    let nonce = random_nonce();
    let aad = block_aad(volume_id, purpose, inode_id, logical, physical, extra);
    let sealed = seal(key, &nonce, &aad, plain)?;
    if sealed.len() != PAYLOAD + 16 {
        return Err(Error::Crypto("sealed block length".into()));
    }
    let mut block = vec![0u8; BLOCK_SIZE as usize];
    block[..24].copy_from_slice(&nonce);
    block[24..].copy_from_slice(&sealed);
    write_exact_at(file, block_offset(physical), &block)?;
    block.zeroize();
    Ok(())
}

fn read_sealed_at(
    file: &mut File,
    total_physical: u64,
    physical: u64,
    key: &[u8; 32],
    volume_id: &[u8; 16],
    purpose: u8,
    inode_id: u64,
    logical: u64,
    extra: u32,
) -> Result<SecretBuf> {
    if physical >= total_physical {
        return Err(Error::Corrupt(format!("block {physical} out of range")));
    }
    let mut block = vec![0u8; BLOCK_SIZE as usize];
    read_exact_at(file, block_offset(physical), &mut block)?;
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&block[..24]);
    let aad = block_aad(volume_id, purpose, inode_id, logical, physical, extra);
    let plain = open(key, &nonce, &aad, &block[24..])
        .map_err(|_| Error::Corrupt(format!("block {physical} failed authentication")))?;
    block.zeroize();
    if plain.len() != PAYLOAD {
        return Err(Error::Corrupt("decrypted block length".into()));
    }
    Ok(SecretBuf::new(plain))
}

fn write_record_chain(
    file: &mut File,
    total_physical: u64,
    blocks: &[u64],
    record: &[u8],
    key: &[u8; 32],
    volume_id: &[u8; 16],
    purpose: u8,
    inode_id: u64,
) -> Result<()> {
    let cap = PAYLOAD - 12;
    let chunks: Vec<&[u8]> = if record.is_empty() {
        vec![b""]
    } else {
        record.chunks(cap).collect()
    };
    if chunks.len() != blocks.len() {
        return Err(Error::Corrupt("inode chain allocation".into()));
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let next = if index + 1 == chunks.len() {
            CHAIN_END
        } else {
            blocks[index + 1]
        };
        let mut plain = vec![0u8; PAYLOAD];
        plain[0..8].copy_from_slice(&next.to_le_bytes());
        plain[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        plain[12..12 + chunk.len()].copy_from_slice(chunk);
        write_sealed_at(
            file,
            total_physical,
            blocks[index],
            &plain,
            key,
            volume_id,
            purpose,
            inode_id,
            index as u64,
            0,
        )?;
        plain.zeroize();
    }
    Ok(())
}

fn write_bitmap(
    file: &mut File,
    total_physical: u64,
    bitmap: &[u8],
    slot: u32,
    blocks_per_slot: u32,
    dek: &[u8; 32],
    volume_id: &[u8; 16],
) -> Result<()> {
    let blocks = u64::from(blocks_per_slot);
    let start = u64::from(slot) * blocks;
    for index in 0..blocks {
        let mut plain = vec![0u8; PAYLOAD];
        let offset = index as usize * PAYLOAD;
        if offset < bitmap.len() {
            let n = (bitmap.len() - offset).min(PAYLOAD);
            plain[..n].copy_from_slice(&bitmap[offset..offset + n]);
        }
        write_sealed_at(
            file,
            total_physical,
            start + index,
            &plain,
            dek,
            volume_id,
            PURPOSE_BITMAP,
            0,
            index,
            slot,
        )?;
        plain.zeroize();
    }
    Ok(())
}

fn write_super_at(
    file: &mut File,
    index: u8,
    header: &SuperHeader,
    body: &SuperBody,
    dek: &[u8; 32],
) -> Result<()> {
    let mut header = *header;
    header.body_nonce = random_nonce();
    let plain = encode_body(body);
    let sealed = seal(dek, &header.body_nonce, &sb_aad(&header.volume_id), &plain)?;
    let raw = encode_superblock(&header, &sealed)?;
    write_exact_at(file, u64::from(index) * SUPER_SIZE as u64, &raw)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::block_offset;

    const PASSWORD: &str = "correct horse battery";

    #[test]
    fn volume_span_can_use_a_prefix() {
        assert_eq!(volume_span(None, 500).unwrap(), 500);
        assert_eq!(volume_span(Some(1 << 30), 500 << 30).unwrap(), 1 << 30);
        assert_eq!(volume_span(Some(500), 500).unwrap(), 500);
        assert_eq!(volume_span(Some(501), 500).unwrap_err().code(), "message");
    }

    #[test]
    fn magic_probe_reads_either_superblock() {
        let missing = tmp("magic-missing");
        assert!(has_volume_magic(&missing.0).is_err());
        let path = tmp("magic");
        std::fs::write(&path.0, [0u8; 16]).unwrap();
        assert!(!has_volume_magic(&path.0).unwrap());
        let mut raw = vec![0u8; 4104];
        raw[4096..4104].copy_from_slice(b"HDNFS2\0\0");
        std::fs::write(&path.0, &raw).unwrap();
        assert!(has_volume_magic(&path.0).unwrap());
    }

    struct Tmp(PathBuf);

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn tmp(label: &str) -> Tmp {
        let mut path = std::env::temp_dir();
        let n = u64::from_le_bytes(random_bytes::<8>());
        path.push(format!("hdnfs-{label}-{}-{n}", std::process::id()));
        Tmp(path)
    }

    fn kdf() -> KdfParams {
        KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn init_at(path: &Path, password: &str, force: bool) -> Result<u64> {
        init_volume(InitOptions {
            path,
            password,
            size: Some(32 * 1024 * 1024),
            force,
            kdf: kdf(),
            progress: None,
        })
    }

    fn setup(label: &str) -> (Tmp, Volume) {
        let path = tmp(label);
        init_at(&path.0, PASSWORD, false).unwrap();
        let volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
        (path, volume)
    }

    fn host_file(label: &str, bytes: &[u8]) -> Tmp {
        let path = tmp(label);
        std::fs::write(&path.0, bytes).unwrap();
        path
    }

    #[test]
    fn batch_stores_a_tree_once_and_abort_discards_it() {
        let (_guard, mut volume) = setup("batch");
        let keep = host_file("keep", b"keep-me");
        let nested = host_file("nested", b"nested-me");
        let generation = volume.generation;
        assert_eq!(volume.stage_mkdir("/docs").unwrap_err().code(), "message");

        volume.begin_batch().unwrap();
        assert_eq!(volume.begin_batch().unwrap_err().code(), "message");
        volume.stage_mkdir("/docs").unwrap();
        volume.stage_put(&keep.0, "/docs/keep.txt").unwrap();
        volume.abort_batch().unwrap();
        assert_eq!(volume.generation, generation);
        assert!(volume.list("/").unwrap().is_empty());

        volume.begin_batch().unwrap();
        volume.stage_mkdir("/docs").unwrap();
        volume.stage_mkdir("/docs").unwrap();
        volume.stage_mkdir("/docs/sub").unwrap();
        volume.stage_put(&keep.0, "/docs/keep.txt").unwrap();
        let used = volume.used_blocks;
        let err = volume.stage_put(&keep.0, "/docs").unwrap_err();
        assert_eq!(err.code(), "type_immutable");
        assert_eq!(volume.used_blocks, used);
        volume.stage_put(&nested.0, "/docs/sub/nested.txt").unwrap();
        volume.finish_batch().unwrap();

        let names = |volume: &mut Volume, path: &str| -> Vec<String> {
            volume
                .list(path)
                .unwrap()
                .into_iter()
                .map(|entry| entry.name)
                .collect()
        };
        assert_eq!(names(&mut volume, "/"), vec!["docs".to_string()]);
        assert_eq!(
            names(&mut volume, "/docs"),
            vec!["keep.txt".to_string(), "sub".to_string()]
        );
        assert_eq!(
            names(&mut volume, "/docs/sub"),
            vec!["nested.txt".to_string()]
        );
        let out = tmp("batch-out");
        volume.get("/docs/keep.txt", &out.0).unwrap();
        assert_eq!(std::fs::read(&out.0).unwrap(), b"keep-me");
        volume.get("/docs/sub/nested.txt", &out.0).unwrap();
        assert_eq!(std::fs::read(&out.0).unwrap(), b"nested-me");

        let newer = host_file("newer", b"newer-body");
        volume.begin_batch().unwrap();
        volume.stage_put(&newer.0, "/docs/keep.txt").unwrap();
        volume.finish_batch().unwrap();
        volume.get("/docs/keep.txt", &out.0).unwrap();
        assert_eq!(std::fs::read(&out.0).unwrap(), b"newer-body");
        assert_eq!(
            names(&mut volume, "/docs/sub"),
            vec!["nested.txt".to_string()]
        );
    }

    #[test]
    fn savepoint_discards_only_later_blocks() {
        let (_guard, mut volume) = setup("savepoint");
        volume.begin_batch().unwrap();
        let first = volume.alloc_block().unwrap();
        let snap = volume.snapshot().unwrap();
        let second = volume.alloc_block().unwrap();
        write_exact_at(
            &mut volume.file,
            block_offset(second),
            &vec![0x11; BLOCK_SIZE as usize],
        )
        .unwrap();
        volume.rollback_to(snap).unwrap();
        assert!(volume.bit(first - volume.allocatable_start));
        assert!(!volume.bit(second - volume.allocatable_start));
        let raw = volume.testing_read_block(second).unwrap();
        assert!(raw.iter().any(|byte| *byte != 0x11));
        volume.abort_batch().unwrap();
        assert!(!volume.bit(first - volume.allocatable_start));
    }

    #[test]
    fn nested_put_get_list_and_type_lock() {
        let (_guard, mut volume) = setup("nested");
        let source = host_file("notes", b"hello volume");
        let written = volume.put(&source.0, "/path1/path2/path3/file").unwrap();
        assert_eq!(written, b"hello volume".len() as u64);

        let root = volume.list("/").unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].name, "path1");
        assert_eq!(root[0].kind, Kind::Dir);

        let nested = volume.list("/path1/path2/path3").unwrap();
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].name, "file");
        assert_eq!(nested[0].kind, Kind::File);
        assert_eq!(nested[0].size, written);

        let out = tmp("out");
        let got = volume.get("/path1/path2/path3/file", &out.0).unwrap();
        assert_eq!(got, written);
        assert_eq!(std::fs::read(&out.0).unwrap(), b"hello volume");

        let stat = volume.stat(Some("/path1/path2/path3/file")).unwrap();
        match stat {
            Stat::Node {
                kind, size, path, ..
            } => {
                assert_eq!(kind, Kind::File);
                assert_eq!(size, written);
                assert_eq!(path, "/path1/path2/path3/file");
            }
            Stat::Volume { .. } => panic!("expected a node"),
        }

        let err = volume.put(&source.0, "/path1/path2/path3").unwrap_err();
        assert_eq!(err.code(), "type_immutable");
        let err = volume.mkdir("/path1/path2/path3/file").unwrap_err();
        assert_eq!(err.code(), "type_immutable");
        let err = volume.mkdir("/path1/path2/path3/file/inside").unwrap_err();
        assert_eq!(err.code(), "not_a_directory");

        volume.mkdir("/path1/path2/path3/subdir").unwrap();
        let err = volume.put(&source.0, "/nope").unwrap();
        assert_eq!(err, written);
        let names: Vec<_> = volume
            .list("/")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names, vec!["nope".to_string(), "path1".to_string()]);
    }

    #[test]
    fn replace_preserves_created_time_and_directory_stays() {
        let (_guard, mut volume) = setup("replace");
        let first = host_file("first", b"one");
        let second = host_file("second", b"two-two");
        volume.put(&first.0, "/path1/file").unwrap();
        let created = match volume.stat(Some("/path1/file")).unwrap() {
            Stat::Node { created, .. } => created,
            Stat::Volume { .. } => panic!("node"),
        };
        volume.put(&second.0, "/path1/file").unwrap();
        match volume.stat(Some("/path1/file")).unwrap() {
            Stat::Node {
                created: again,
                size,
                ..
            } => {
                assert_eq!(again, created);
                assert_eq!(size, 7);
            }
            Stat::Volume { .. } => panic!("node"),
        }
        let out = tmp("replaced");
        volume.get("/path1/file", &out.0).unwrap();
        assert_eq!(std::fs::read(&out.0).unwrap(), b"two-two");
        assert_eq!(volume.list("/path1").unwrap().len(), 1);
    }

    #[test]
    fn delete_scrubs_and_allows_the_other_type() {
        let (_guard, mut volume) = setup("delete");
        let source = host_file("secret", b"unique-marker-0123456789-abcdef");
        volume.put(&source.0, "/dir/secret").unwrap();
        let block = volume.testing_extents("/dir/secret").unwrap()[0];
        let before = volume.testing_read_block(block).unwrap();
        let err = volume.delete("/dir").unwrap_err();
        assert_eq!(err.code(), "not_empty");
        volume.delete("/dir/secret").unwrap();
        let after = volume.testing_read_block(block).unwrap();
        assert_ne!(before, after);
        assert_eq!(volume.list("/dir").unwrap().len(), 0);
        let err = volume.get("/dir/secret", &tmp("missing").0).unwrap_err();
        assert_eq!(err.code(), "not_found");
        volume.delete("/dir").unwrap();
        volume.put(&source.0, "/dir").unwrap();
        match volume.stat(Some("/dir")).unwrap() {
            Stat::Node { kind, .. } => assert_eq!(kind, Kind::File),
            Stat::Volume { .. } => panic!("node"),
        }
        volume.delete("/dir").unwrap();
        volume.mkdir("/dir").unwrap();
        match volume.stat(Some("/dir")).unwrap() {
            Stat::Node { kind, .. } => assert_eq!(kind, Kind::Dir),
            Stat::Volume { .. } => panic!("node"),
        }
    }

    #[test]
    fn empty_and_multiblock_files_roundtrip() {
        let (_guard, mut volume) = setup("sizes");
        let empty = host_file("empty", b"");
        assert_eq!(volume.put(&empty.0, "/empty").unwrap(), 0);
        let out = tmp("empty-out");
        assert_eq!(volume.get("/empty", &out.0).unwrap(), 0);
        assert!(std::fs::read(&out.0).unwrap().is_empty());

        let mut data = vec![0u8; PAYLOAD + 10];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let big = host_file("big", &data);
        assert_eq!(volume.put(&big.0, "/big").unwrap(), data.len() as u64);
        assert_eq!(volume.testing_extents("/big").unwrap().len(), 2);
        let out = tmp("big-out");
        volume.get("/big", &out.0).unwrap();
        assert_eq!(std::fs::read(&out.0).unwrap(), data);
    }

    #[test]
    fn get_with_reports_progress_and_stops_before_rename() {
        let (_guard, mut volume) = setup("get-progress");
        let source = host_file("body", b"abcdefghijklmnopqrstuvwxyz");
        volume.put(&source.0, "/note").unwrap();
        let out = tmp("note-out");
        let mut seen = Vec::new();
        let n = volume
            .get_with("/note", &out.0, &mut |written, total| {
                seen.push((written, total));
                Ok(())
            })
            .unwrap();
        assert_eq!(n, 26);
        assert_eq!(seen.first(), Some(&(0, 26)));
        assert_eq!(seen.last(), Some(&(26, 26)));
        assert_eq!(
            std::fs::read(&out.0).unwrap(),
            b"abcdefghijklmnopqrstuvwxyz"
        );

        let replaced = tmp("note-old");
        std::fs::write(&replaced.0, b"old").unwrap();
        let err = volume
            .get_with("/note", &replaced.0, &mut |written, _| {
                if written > 0 {
                    return Err(Error::Message("get canceled".into()));
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(err.to_string(), "get canceled");
        assert_eq!(std::fs::read(&replaced.0).unwrap(), b"old");
    }

    #[test]
    fn tamper_and_bad_password_fail_closed() {
        let path = tmp("tamper");
        init_at(&path.0, PASSWORD, false).unwrap();
        {
            let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
            let source = host_file("body", b"authenticated");
            volume.put(&source.0, "/a").unwrap();
            let block = volume.testing_extents("/a").unwrap()[0];
            volume.testing_poke(block_offset(block) + 80).unwrap();
            let err = volume.get("/a", &tmp("bad-out").0).unwrap_err();
            assert_eq!(err.code(), "corrupt");
        }
        match Volume::open(&path.0, "another password!!", LockMode::Shared) {
            Err(err) => assert_eq!(err.code(), "wrong_password"),
            Ok(_) => panic!("wrong password opened the volume"),
        }
        {
            let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
            volume.testing_poke(300).unwrap();
        }
        Volume::open(&path.0, PASSWORD, LockMode::Shared).unwrap();
        {
            let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
            volume.testing_poke(300).unwrap();
            volume.testing_poke(4096 + 300).unwrap();
        }
        match Volume::open(&path.0, PASSWORD, LockMode::Shared) {
            Err(err) => assert_eq!(err.code(), "corrupt"),
            Ok(_) => panic!("damaged headers still opened"),
        }
    }

    #[test]
    fn reinit_requires_force_and_installs_a_new_key() {
        let path = tmp("reinit");
        init_at(&path.0, PASSWORD, false).unwrap();
        {
            let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
            let source = host_file("keep", b"secret");
            volume.put(&source.0, "/secret").unwrap();
        }
        let err = init_at(&path.0, "a different password", false).unwrap_err();
        assert_eq!(err.code(), "denied");
        init_at(&path.0, "a different password", true).unwrap();
        match Volume::open(&path.0, PASSWORD, LockMode::Shared) {
            Err(err) => assert_eq!(err.code(), "wrong_password"),
            Ok(_) => panic!("old password opened the reinitialized volume"),
        }
        let mut volume =
            Volume::open(&path.0, "a different password", LockMode::Exclusive).unwrap();
        assert!(volume.list("/").unwrap().is_empty());
        match volume.stat(None).unwrap() {
            Stat::Volume {
                used_blocks,
                free_blocks,
                ..
            } => {
                assert_eq!(used_blocks, 1);
                assert!(free_blocks > 0);
            }
            Stat::Node { .. } => panic!("volume"),
        }
    }

    #[test]
    fn shared_lock_cannot_mutate_and_paths_are_rejected() {
        let path = tmp("shared");
        init_at(&path.0, PASSWORD, false).unwrap();
        let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Shared).unwrap();
        let source = host_file("x", b"x");
        assert_eq!(volume.put(&source.0, "/x").unwrap_err().code(), "denied");
        assert_eq!(volume.mkdir("/x").unwrap_err().code(), "denied");
        assert_eq!(parse_path("/a/../b").unwrap_err().code(), "invalid_path");
        let err = init_volume(InitOptions {
            path: &tmp("tiny").0,
            password: PASSWORD,
            size: Some(1024 * 1024),
            force: false,
            kdf: kdf(),
            progress: None,
        })
        .unwrap_err();
        assert_eq!(err.code(), "message");
    }

    impl Volume {
        fn testing_extents(&mut self, path: &str) -> Result<Vec<u64>> {
            let parsed = parse_path(path)?;
            let inode = self.walk(&parsed.components)?;
            Ok(inode.content_blocks)
        }

        fn testing_poke(&mut self, offset: u64) -> Result<()> {
            let mut byte = [0u8; 1];
            read_exact_at(&mut self.file, offset, &mut byte)?;
            byte[0] ^= 0xff;
            write_exact_at(&mut self.file, offset, &byte)?;
            self.file.sync_all()?;
            self.block_cache.clear();
            Ok(())
        }

        fn testing_read_block(&mut self, physical: u64) -> Result<Vec<u8>> {
            let mut buf = vec![0u8; BLOCK_SIZE as usize];
            read_exact_at(&mut self.file, block_offset(physical), &mut buf)?;
            Ok(buf)
        }
    }
}
