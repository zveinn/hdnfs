use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    self, derive_kek, fill_random, open, random_bytes, random_nonce, seal, unwrap_key, wrap_key,
    KdfParams, SecretBuf,
};
use crate::error::{Error, Result};
use crate::format::{
    bitmap_len, bitmap_parity_blocks, block_aad, block_offset, chain_parity_len,
    content_parity_len, decode_body, decode_entries, decode_inode_record, decode_superblock_header,
    dek_aad, div_ceil, encode_body, encode_entries, encode_inode_record, encode_superblock,
    file_key_aad, geometry, inode_chain_blocks, mask_bitmap, prefer_index, sb_aad, sealed_body,
    slot_span, validate_body, InodeRecord, RawEntry, SuperBody, SuperHeader, BLOCK_SIZE,
    BODY_PLAIN_LEN, CHAIN_END, DATA_STRIPE, HEADER_BYTES, KIND_DIR, KIND_FILE, MAGIC,
    MAX_DIR_BYTES, PARITY_COUNT, PAYLOAD, PURPOSE_BITMAP, PURPOSE_DIR, PURPOSE_FILE, PURPOSE_INODE,
    PURPOSE_PARITY, STRIPE_GAP, SUPER_COPIES, SUPER_SIZE,
};
use crate::pathutil::{display_path, parse_path};
use crate::reed_solomon;
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
    content_parity: Vec<u64>,
    chain_parity: Vec<u64>,
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
            content_parity: self.content_parity.clone(),
            chain_parity: self.chain_parity.clone(),
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
            content_parity: Vec::new(),
            chain_parity: Vec::new(),
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
    content_parity: Vec<u64>,
    chain_parity: Vec<u64>,
}

struct PendingPut {
    parent: Vec<String>,
    entry: RawEntry,
    replaced: Option<StagedReplace>,
}

struct Savepoint {
    bitmap: Vec<u8>,
    root: u64,
    root_parity: [u64; 3],
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
    root_parity_backup: [u64; 3],
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
    root_parity: [u64; 3],
    created: i64,
    bitmap_slot: u32,
    bitmap_blocks_per_slot: u32,
    bitmap: Vec<u8>,
    /// The active bitmap was rebuilt from parity and still needs a durable rewrite.
    bitmap_needs_heal: bool,
    /// A read rebuilt a block in memory. `get` persists that repair.
    repair_hint: bool,
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
        self.dek.zeroize();
        unixutil::munlock_bytes(&self.dek[..]);
        let _ = unixutil::flock_unlock(&self.file);
    }
}

/// True when any of the three superblock copies starts with the HDNFS2 magic.
/// A short or absent header is false. This does not check the password.
pub fn has_volume_magic(path: &Path) -> Result<bool> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    for index in 0..SUPER_COPIES {
        if magic_at(&mut file, index as u64 * SUPER_SIZE as u64)? {
            return Ok(true);
        }
    }
    Ok(false)
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
        lock_file(&file, true)?;
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
    if device_size < HEADER_BYTES {
        return Err(Error::Message(format!(
            "volume must be at least {} bytes",
            crate::format::minimum_volume_bytes()
        )));
    }
    let total_physical = (device_size - HEADER_BYTES) / BLOCK_SIZE;
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
    let addressable = HEADER_BYTES + total_physical * BLOCK_SIZE;
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
    report_progress(
        &mut progress,
        "deriving",
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
        parity: Vec::new(),
    });
    let root_plain = chain_plain(CHAIN_END, &record);
    let root_parity_plain = reed_solomon::encode(&[&root_plain[..]])?;
    let mut taken = vec![root_physical];
    let mut root_parity = [0u64; 3];
    for (index, plain) in root_parity_plain.iter().enumerate() {
        let physical = pick_init_block(allocatable_start, data_blocks, &taken)?;
        root_parity[index] = physical;
        taken.push(physical);
        let _ = plain;
    }
    write_sealed_at(
        file,
        total_physical,
        root_physical,
        &root_plain,
        &dek,
        &volume_id,
        PURPOSE_INODE,
        1,
        0,
        0,
    )?;
    for (index, plain) in root_parity_plain.iter().enumerate() {
        write_sealed_at(
            file,
            total_physical,
            root_parity[index],
            plain,
            &dek,
            &volume_id,
            PURPOSE_PARITY,
            1,
            0,
            index as u32,
        )?;
    }

    let mut bitmap = vec![0u8; bitmap_len(data_blocks)];
    for physical in &taken {
        let index = (physical - allocatable_start) as usize;
        bitmap[index / 8] |= 1 << (index % 8);
    }
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
        used_blocks: taken.len() as u64,
        next_inode_id: 2,
        root_inode_id: 1,
        root_inode_block: root_physical,
        created_unix: created,
        bitmap_slot: 0,
        bitmap_blocks_per_slot: blocks_per_slot,
        flags: 0,
        root_parity,
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
    write_super_at(file, 2, &header_base, &body, &dek)?;
    file.sync_all()?;
    Ok(addressable)
}

fn pick_init_block(start: u64, count: u64, taken: &[u64]) -> Result<u64> {
    let mut fallback = None;
    for index in 0..count {
        let physical = start + index;
        if taken.contains(&physical) {
            continue;
        }
        if taken
            .iter()
            .all(|other| physical.abs_diff(*other) >= STRIPE_GAP)
        {
            return Ok(physical);
        }
        if fallback.is_none() {
            fallback = Some(physical);
        }
    }
    fallback.ok_or(Error::Full)
}

fn lock_file(file: &File, exclusive: bool) -> Result<()> {
    let locked = if exclusive {
        unixutil::flock_exclusive(file)
    } else {
        unixutil::flock_shared(file)
    };
    match locked {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::WouldBlock => {
            Err(Error::Denied("volume is in use".into()))
        }
        Err(err) => Err(err.into()),
    }
}

fn clear_magic(file: &mut File) -> Result<()> {
    for index in 0..SUPER_COPIES {
        write_exact_at(file, index as u64 * SUPER_SIZE as u64, &[0u8; 8])?;
    }
    file.sync_all()?;
    Ok(())
}

impl Volume {
    pub fn open(path: &Path, password: &str, lock: LockMode) -> Result<Self> {
        crate::password::validate_password(password)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        lock_file(&file, matches!(lock, LockMode::Exclusive))?;
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

    /// Writes file bytes. Missing parent directories are created. An existing file is replaced.
    pub fn write_bytes(&mut self, dest: &str, data: &[u8]) -> Result<u64> {
        let parsed = parse_path(dest)?;
        if parsed.components.is_empty() {
            return Err(type_change("/", Kind::Dir));
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
        self.with_txn(|vol| vol.write_bytes_txn(&parent, &name, data))
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
        // A directory or inode block cached earlier would hide damage on the device.
        self.block_cache.clear();
        self.repair_hint = false;
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
        if self.repair_hint || self.bitmap_needs_heal {
            if !self.exclusive {
                return Err(Error::Denied("repair needs an exclusive lock".into()));
            }
            let comps = parsed.components.clone();
            self.with_txn(|vol| vol.repair_path(&comps))?;
            self.bitmap_needs_heal = false;
        }
        std::fs::rename(&tmp, dest)?;
        guard.disarm();
        Ok(inode.size)
    }

    /// Copies the initialized image, byte for byte, into `dest`.
    /// The image is the header and every block. A callback error deletes the partial file.
    pub fn backup(
        &mut self,
        dest: &Path,
        progress: &mut dyn FnMut(u64, u64) -> Result<()>,
    ) -> Result<u64> {
        if !self.exclusive {
            return Err(Error::Denied("volume is open read-only".into()));
        }
        if dest.as_os_str().is_empty() {
            return Err(Error::Message("empty input".into()));
        }
        if let Ok(meta) = std::fs::metadata(dest) {
            if meta.is_dir() {
                return Err(Error::Message(format!("{} is a directory", dest.display())));
            }
        }
        if is_open_volume(&self.file, dest) {
            return Err(Error::Denied("backup path is the open volume".into()));
        }
        let total = HEADER_BYTES + self.total_physical * BLOCK_SIZE;
        progress(0, total)?;
        let tmp = partial_path(dest);
        let mut guard = RemoveOnDrop(Some(tmp.clone()));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let mut offset = 0u64;
        let mut buf = vec![0u8; BLOCK_SIZE as usize];
        while offset < total {
            let n = usize::try_from((total - offset).min(BLOCK_SIZE)).unwrap();
            read_exact_at(&mut self.file, offset, &mut buf[..n])?;
            output.write_all(&buf[..n])?;
            offset += n as u64;
            progress(offset, total)?;
        }
        output.sync_all()?;
        drop(output);
        std::fs::rename(&tmp, dest)?;
        let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o600));
        guard.disarm();
        Ok(total)
    }

    /// Reads a file into memory. Damage that can be rebuilt is written back when the lock is exclusive.
    pub fn read_bytes(&mut self, src: &str) -> Result<Zeroizing<Vec<u8>>> {
        let parsed = parse_path(src)?;
        if parsed.components.is_empty() {
            return Err(Error::IsDirectory("/".into()));
        }
        let shown = display_path(&parsed.components);
        self.block_cache.clear();
        self.repair_hint = false;
        let inode = self.walk(&parsed.components)?;
        if inode.kind != Kind::File {
            return Err(Error::IsDirectory(shown));
        }
        let mut output = Vec::new();
        self.stream_to(&inode, &mut output, &mut |_, _| Ok(()))?;
        if self.repair_hint || self.bitmap_needs_heal {
            if !self.exclusive {
                return Err(Error::Denied("repair needs an exclusive lock".into()));
            }
            let comps = parsed.components.clone();
            self.with_txn(|vol| vol.repair_path(&comps))?;
            self.bitmap_needs_heal = false;
        }
        Ok(Zeroizing::new(output))
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
                    size: HEADER_BYTES + self.total_physical * BLOCK_SIZE,
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
        let raw = [
            read_super_raw(&mut file, 0)?,
            read_super_raw(&mut file, 1)?,
            read_super_raw(&mut file, 2)?,
        ];
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
        let generations = [
            candidates
                .iter()
                .find(|candidate| candidate.index == 0)
                .map(|candidate| candidate.body.generation),
            candidates
                .iter()
                .find(|candidate| candidate.index == 1)
                .map(|candidate| candidate.body.generation),
            candidates
                .iter()
                .find(|candidate| candidate.index == 2)
                .map(|candidate| candidate.body.generation),
        ];
        let winner = prefer_index(&generations)?;
        let best = candidates
            .into_iter()
            .find(|candidate| candidate.index == winner)
            .ok_or_else(|| Error::Corrupt("superblock".into()))?;
        let dek = Box::new(best.dek);
        unixutil::mlock_bytes(&dek[..]).map_err(|err| {
            Error::Message(format!("failed to lock the volume key in memory: {err}"))
        })?;

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
            root_parity: best.body.root_parity,
            created: best.body.created_unix,
            bitmap_slot: best.body.bitmap_slot,
            bitmap_blocks_per_slot: best.body.bitmap_blocks_per_slot,
            bitmap: Vec::new(),
            bitmap_needs_heal: false,
            repair_hint: false,
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
        let root_parity = volume.root_parity;
        let root =
            volume.load_inode(volume.root_inode_block, volume.root_inode_id, &root_parity)?;
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
            root_parity_backup: self.root_parity,
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
            root_parity: self.root_parity,
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
        let (created, replaced) =
            match entries.binary_search_by(|entry| entry.name.as_str().cmp(name.as_str())) {
                Ok(index) => {
                    if Kind::from_u8(entries[index].kind)? != Kind::File {
                        return Err(type_change(&shown, Kind::Dir));
                    }
                    let old = self.load_inode(
                        entries[index].inode_block,
                        entries[index].inode_id,
                        &entries[index].chain_parity,
                    )?;
                    (
                        old.created,
                        Some(StagedReplace {
                            inode_id: old.id,
                            stored_at: old.stored_at,
                            content_blocks: old.content_blocks.clone(),
                            content_parity: old.content_parity.clone(),
                            chain_parity: old.chain_parity.clone(),
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
        let (file_block, chain_parity) = self.store_inode(&file_inode)?;
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
                    chain_parity,
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
            for block in old.content_blocks.iter().chain(old.content_parity.iter()) {
                self.free_block(*block)?;
            }
            self.free_chain_blocks(old.stored_at, old.inode_id, &old.chain_parity)?;
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
        let commit_at = (0..SUPER_COPIES as u8)
            .find(|index| *index != self.active_super)
            .ok_or_else(|| Error::Corrupt("superblock index".into()))?;
        self.write_bitmap_slot(new_slot)?;
        self.file.sync_all()?;
        self.write_super_copy(commit_at, new_gen, new_slot)?;
        self.commit_durable = true;
        self.generation = new_gen;
        self.bitmap_slot = new_slot;
        self.active_super = commit_at;
        self.file.sync_all()?;
        for index in 0..SUPER_COPIES as u8 {
            if index != commit_at {
                self.write_super_copy(index, new_gen, new_slot)?;
            }
        }
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
        self.root_parity = txn.root_parity_backup;
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
        self.root_parity = snap.root_parity;
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

    /// Prefer a free block at least `STRIPE_GAP` away from every anchor.
    /// A volume too small for that gap takes any free block.
    fn alloc_block_away(&mut self, anchors: &[u64]) -> Result<u64> {
        if let Some(block) = self.find_free(anchors, true)? {
            return Ok(block);
        }
        self.find_free(anchors, false)?.ok_or(Error::Full)
    }

    fn find_free(&mut self, anchors: &[u64], separated: bool) -> Result<Option<u64>> {
        let freed = self
            .txn
            .as_ref()
            .ok_or_else(|| Error::Message("no transaction".into()))?
            .freed
            .clone();
        let count = self.data_block_count;
        if count == 0 {
            return Ok(None);
        }
        let start = self.alloc_cursor % count;
        for step in 0..count {
            let index = (start + step) % count;
            let physical = self.allocatable_start + index;
            if freed.contains(&physical) || self.bit(index) {
                continue;
            }
            if separated
                && anchors
                    .iter()
                    .any(|anchor| physical.abs_diff(*anchor) < STRIPE_GAP)
            {
                continue;
            }
            self.set_bit(index, true);
            self.used_blocks += 1;
            self.alloc_cursor = (index + 1) % count;
            self.txn.as_mut().unwrap().allocated.push(physical);
            self.block_cache.forget(physical);
            return Ok(Some(physical));
        }
        Ok(None)
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

    fn slot_base(&self, slot: u32) -> u64 {
        u64::from(slot) * slot_span(u64::from(self.bitmap_blocks_per_slot))
    }

    fn read_bitmap(&mut self) -> Result<Vec<u8>> {
        let blen = bitmap_len(self.data_block_count);
        let dek = self.dek_copy();
        let blocks = u64::from(self.bitmap_blocks_per_slot);
        let start = self.slot_base(self.bitmap_slot);
        let mut plains: Vec<Option<SecretBuf>> = Vec::with_capacity(blocks as usize);
        let mut missing = false;
        for index in 0..blocks {
            match self.read_sealed(
                start + index,
                &dek,
                PURPOSE_BITMAP,
                0,
                index,
                self.bitmap_slot,
            ) {
                Ok(plain) => plains.push(Some(plain)),
                Err(Error::Corrupt(_)) => {
                    missing = true;
                    plains.push(None);
                }
                Err(err) => return Err(err),
            }
        }
        if missing {
            self.reconstruct_bitmap(start, &mut plains)?;
            self.bitmap_needs_heal = true;
        }
        let mut bitmap = vec![0u8; blen];
        for (index, plain) in plains.iter().enumerate() {
            let plain = plain
                .as_ref()
                .ok_or_else(|| Error::Corrupt("bitmap block".into()))?;
            let offset = index * PAYLOAD;
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

    fn reconstruct_bitmap(&mut self, start: u64, plains: &mut [Option<SecretBuf>]) -> Result<()> {
        let blocks = plains.len();
        let dek = self.dek_copy();
        let mut stripe = 0usize;
        while stripe * (DATA_STRIPE as usize) < blocks {
            let begin = stripe * DATA_STRIPE as usize;
            let end = (begin + DATA_STRIPE as usize).min(blocks);
            if plains[begin..end].iter().all(|plain| plain.is_some()) {
                stripe += 1;
                continue;
            }
            let mut shards: [Option<Vec<u8>>; reed_solomon::STRIPE] = std::array::from_fn(|_| None);
            let zeros = vec![0u8; PAYLOAD];
            for index in 0..DATA_STRIPE as usize {
                let slot = begin + index;
                if slot < end {
                    if let Some(plain) = &plains[slot] {
                        shards[index] = Some(plain.to_vec());
                    }
                } else {
                    shards[index] = Some(zeros.clone());
                }
            }
            let mut failed = end
                - begin
                - plains[begin..end]
                    .iter()
                    .filter(|plain| plain.is_some())
                    .count();
            for parity in 0..PARITY_COUNT as usize {
                let physical = start + blocks as u64 + stripe as u64 * PARITY_COUNT + parity as u64;
                match self.read_sealed(
                    physical,
                    &dek,
                    PURPOSE_PARITY,
                    0,
                    stripe as u64,
                    parity as u32,
                ) {
                    Ok(plain) => shards[DATA_STRIPE as usize + parity] = Some(plain.to_vec()),
                    Err(Error::Corrupt(_)) => failed += 1,
                    Err(err) => return Err(err),
                }
            }
            if failed > PARITY_COUNT as usize {
                return Err(Error::Corrupt("unrepairable bitmap".into()));
            }
            let view: [Option<&[u8]>; reed_solomon::STRIPE] =
                std::array::from_fn(|index| shards[index].as_deref());
            let rebuilt = reed_solomon::reconstruct(&view)?;
            for index in 0..(end - begin) {
                if plains[begin + index].is_none() {
                    plains[begin + index] = Some(SecretBuf::new(rebuilt[index].clone()));
                }
            }
            stripe += 1;
        }
        Ok(())
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
            root_parity: self.root_parity,
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

    fn load_inode(&mut self, block: u64, expected_id: u64, chain_parity: &[u64]) -> Result<Inode> {
        let record_bytes = self.read_inode_record(block, expected_id, chain_parity)?;
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
        if record.parity.len() as u64 != content_parity_len(expect) {
            return Err(Error::Corrupt("content parity".into()));
        }
        for physical in record.blocks.iter().chain(record.parity.iter()) {
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
            content_parity: record.parity,
            chain_parity: chain_parity.to_vec(),
            stored_at: block,
        })
    }

    fn read_inode_record(
        &mut self,
        first: u64,
        inode_id: u64,
        chain_parity: &[u64],
    ) -> Result<Vec<u8>> {
        let chain = self.read_chain(first, inode_id, chain_parity)?;
        Ok(chain.record)
    }

    fn store_inode(&mut self, inode: &Inode) -> Result<(u64, Vec<u64>)> {
        if inode.content_parity.len() as u64
            != content_parity_len(inode.content_blocks.len() as u64)
        {
            return Err(Error::Corrupt("content parity".into()));
        }
        let dek = self.dek_copy();
        let volume_id = self.volume_id;
        let record = seal_inode(inode, &volume_id, &dek)?;
        let cap = PAYLOAD - 12;
        let count = record.len().div_ceil(cap).max(1);
        if count as u64 != inode_chain_blocks(inode.content_blocks.len() as u64) {
            return Err(Error::Corrupt("inode chain size".into()));
        }
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            let physical = self.alloc_block_away(&blocks)?;
            blocks.push(physical);
        }
        let plains = chain_plains(&blocks, &record)?;
        let mut parity = Vec::new();
        let stripe_count = div_ceil(blocks.len() as u64, DATA_STRIPE) as usize;
        for stripe in 0..stripe_count {
            let begin = stripe * DATA_STRIPE as usize;
            let end = (begin + DATA_STRIPE as usize).min(plains.len());
            let refs: Vec<&[u8]> = plains[begin..end].iter().map(Vec::as_slice).collect();
            let encoded = reed_solomon::encode(&refs)?;
            for (index, plain) in encoded.iter().enumerate() {
                let mut anchors = blocks[begin..end].to_vec();
                anchors.extend(parity[stripe * PARITY_COUNT as usize..].iter().copied());
                let physical = self.alloc_block_away(&anchors)?;
                self.write_sealed(
                    physical,
                    plain,
                    &dek,
                    PURPOSE_PARITY,
                    inode.id,
                    stripe as u64,
                    index as u32,
                )?;
                parity.push(physical);
            }
        }
        let total = self.total_physical;
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
        Ok((blocks[0], parity))
    }

    fn free_chain_blocks(&mut self, first: u64, inode_id: u64, parity: &[u64]) -> Result<()> {
        if first == u64::MAX {
            return Err(Error::Corrupt("inode was never stored".into()));
        }
        let blocks = match self.chain_addresses(first, inode_id) {
            Ok(blocks) => blocks,
            Err(Error::Corrupt(_)) => vec![first],
            Err(err) => return Err(err),
        };
        for block in blocks {
            self.free_block(block)?;
        }
        for block in parity {
            self.free_block(*block)?;
        }
        Ok(())
    }

    fn chain_addresses(&mut self, first: u64, inode_id: u64) -> Result<Vec<u64>> {
        let dek = self.dek_copy();
        let mut block = first;
        let mut seen = Vec::new();
        loop {
            if seen.contains(&block) || seen.len() > 1024 {
                return Err(Error::Corrupt("inode chain".into()));
            }
            self.check_data_block(block)?;
            let logical = seen.len() as u64;
            let plain = self.read_sealed(block, &dek, PURPOSE_INODE, inode_id, logical, 0)?;
            seen.push(block);
            let (next, _) = split_chain(&plain)?;
            if next == CHAIN_END {
                break;
            }
            block = next;
        }
        Ok(seen)
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
        if inode.content_blocks.len() as u64 != expect
            || inode.content_parity.len() as u64 != content_parity_len(expect)
        {
            return Err(Error::Corrupt("block count mismatch".into()));
        }
        if inode.size == 0 {
            return Ok(SecretBuf::new(Vec::new()));
        }
        let mut out = vec![0u8; inode.size as usize];
        let key = inode.file_key.clone();
        let mut offset = 0usize;
        let mut index = 0usize;
        while index < inode.content_blocks.len() {
            let count = (inode.content_blocks.len() - index).min(DATA_STRIPE as usize);
            let plains = self.read_content_stripe(inode, &key, purpose, index, count)?;
            for (delta, plain) in plains.iter().enumerate() {
                let take = (out.len() - offset).min(PAYLOAD);
                if index + delta + 1 == inode.content_blocks.len()
                    && plain[take..].iter().any(|byte| *byte != 0)
                {
                    return Err(Error::Corrupt("content padding".into()));
                }
                out[offset..offset + take].copy_from_slice(&plain[..take]);
                offset += take;
            }
            index += count;
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
        let old_blocks = std::mem::take(&mut inode.content_blocks);
        let old_parity = std::mem::take(&mut inode.content_parity);
        for block in old_blocks.into_iter().chain(old_parity) {
            self.free_block(block)?;
        }
        if data.is_empty() {
            inode.size = 0;
            inode.modified = now_unix();
            return Ok(());
        }
        let mut pending = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + PAYLOAD).min(data.len());
            let mut plain = vec![0u8; PAYLOAD];
            plain[..end - offset].copy_from_slice(&data[offset..end]);
            pending.push(plain);
            offset = end;
            if pending.len() == DATA_STRIPE as usize {
                self.flush_stripe(inode, &mut pending, purpose)?;
            }
        }
        self.flush_stripe(inode, &mut pending, purpose)?;
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
        if inode.content_blocks.len() as u64 != expect
            || inode.content_parity.len() as u64 != content_parity_len(expect)
        {
            return Err(Error::Corrupt("block count mismatch".into()));
        }
        let key = inode.file_key.clone();
        let mut remaining = inode.size;
        let mut written = 0u64;
        progress(0, inode.size)?;
        let mut index = 0usize;
        while index < inode.content_blocks.len() {
            let count = (inode.content_blocks.len() - index).min(DATA_STRIPE as usize);
            let plains = self.read_content_stripe(inode, &key, PURPOSE_FILE, index, count)?;
            for (delta, plain) in plains.iter().enumerate() {
                let take = usize::try_from(remaining.min(PAYLOAD as u64)).unwrap_or(PAYLOAD);
                if index + delta + 1 == inode.content_blocks.len()
                    && plain[take..].iter().any(|byte| *byte != 0)
                {
                    return Err(Error::Corrupt("content padding".into()));
                }
                out.write_all(&plain[..take])?;
                written += take as u64;
                remaining -= take as u64;
                progress(written, inode.size)?;
            }
            index += count;
        }
        if remaining != 0 {
            return Err(Error::Corrupt("short file".into()));
        }
        Ok(())
    }

    fn write_file_stream(&mut self, inode: &mut Inode, src: &Path) -> Result<()> {
        let mut input = File::open(src)?;
        let mut buf = vec![0u8; PAYLOAD];
        let mut total = 0u64;
        let mut pending = Vec::new();
        loop {
            let n = read_chunk(&mut input, &mut buf)?;
            if n == 0 {
                break;
            }
            if n < PAYLOAD {
                buf[n..].fill(0);
            }
            pending.push(buf.clone());
            total += n as u64;
            if pending.len() == DATA_STRIPE as usize {
                self.flush_stripe(inode, &mut pending, PURPOSE_FILE)?;
            }
            if n < PAYLOAD {
                break;
            }
        }
        self.flush_stripe(inode, &mut pending, PURPOSE_FILE)?;
        buf.zeroize();
        inode.size = total;
        inode.modified = now_unix();
        Ok(())
    }

    fn flush_stripe(
        &mut self,
        inode: &mut Inode,
        pending: &mut Vec<Vec<u8>>,
        purpose: u8,
    ) -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        let mut data_blocks = Vec::with_capacity(pending.len());
        for _ in pending.iter() {
            data_blocks.push(self.alloc_block_away(&data_blocks)?);
        }
        let refs: Vec<&[u8]> = pending.iter().map(Vec::as_slice).collect();
        let parity = reed_solomon::encode(&refs)?;
        let mut parity_blocks = Vec::with_capacity(PARITY_COUNT as usize);
        for _ in 0..PARITY_COUNT {
            let mut anchors = data_blocks.clone();
            anchors.extend_from_slice(&parity_blocks);
            parity_blocks.push(self.alloc_block_away(&anchors)?);
        }
        let key = inode.file_key.clone();
        let id = inode.id;
        let base = inode.content_blocks.len() as u64;
        let stripe = inode.content_parity.len() as u64 / PARITY_COUNT;
        for (offset, (physical, plain)) in data_blocks.iter().zip(pending.iter()).enumerate() {
            self.write_sealed(*physical, plain, &key, purpose, id, base + offset as u64, 0)?;
        }
        for (index, (physical, plain)) in parity_blocks.iter().zip(parity.iter()).enumerate() {
            self.write_sealed(
                *physical,
                plain,
                &key,
                PURPOSE_PARITY,
                id,
                stripe,
                index as u32,
            )?;
        }
        inode.content_blocks.extend(data_blocks);
        inode.content_parity.extend(parity_blocks);
        for plain in pending.iter_mut() {
            plain.zeroize();
        }
        pending.clear();
        Ok(())
    }

    fn collect_inodes(&mut self, comps: &[String]) -> Result<Vec<Inode>> {
        let mut out = Vec::new();
        let root_parity = self.root_parity;
        let root = self.load_inode(self.root_inode_block, self.root_inode_id, &root_parity)?;
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
                    let child =
                        self.load_inode(entry.inode_block, entry.inode_id, &entry.chain_parity)?;
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
        let old_parity = dir.chain_parity.clone();
        let (new_block, new_parity) = self.store_inode(&dir)?;
        self.free_chain_blocks(old, dir.id, &old_parity)?;
        dir.stored_at = new_block;
        dir.chain_parity = new_parity.clone();
        if comps.is_empty() {
            self.root_inode_block = new_block;
            self.root_parity = parity3(&new_parity)?;
            return Ok(());
        }
        let parent_comps = &comps[..comps.len() - 1];
        let name = comps[comps.len() - 1].clone();
        let parent = self.walk(parent_comps)?;
        let mut parent_entries = self.read_entries(&parent)?;
        match parent_entries.iter_mut().find(|entry| entry.name == name) {
            Some(entry) => {
                entry.inode_block = new_block;
                entry.chain_parity = new_parity;
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
                chain_parity: vec![0, 0, 0],
            },
        );
        let parent_bytes = encode_entries(&tentative)?.len() as u64;
        // The new directory is empty: one chain block and its three parity blocks.
        let mut need = blocks_for(0);
        need += blocks_for(div_ceil(parent_bytes, PAYLOAD as u64));
        for inode in &chain[..chain.len() - 1] {
            need += blocks_for(div_ceil(inode.size, PAYLOAD as u64));
        }
        self.ensure_space(need)?;
        let id = self.alloc_inode_id();
        let child = Inode::new(Kind::Dir, id, now_unix());
        let (child_block, child_parity) = self.store_inode(&child)?;
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
                chain_parity: child_parity,
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
                let old = self.load_inode(
                    entries[index].inode_block,
                    entries[index].inode_id,
                    &entries[index].chain_parity,
                )?;
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
            chain_parity: vec![0, 0, 0],
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
        let (file_block, chain_parity) = self.store_inode(&file_inode)?;
        let entry = RawEntry {
            name: name.to_string(),
            inode_id: id,
            kind: KIND_FILE,
            inode_block: file_block,
            size: file_inode.size,
            chain_parity,
        };
        match entries.binary_search_by(|entry| entry.name.as_str().cmp(name)) {
            Ok(index) => entries[index] = entry,
            Err(index) => entries.insert(index, entry),
        }
        self.save_dir(parent_comps, parent, entries)?;
        if let Some(old) = old {
            self.free_content(&old)?;
            self.free_chain_blocks(old.stored_at, old.id, &old.chain_parity)?;
        }
        Ok(file_inode.size)
    }

    fn write_bytes_txn(&mut self, parent_comps: &[String], name: &str, data: &[u8]) -> Result<u64> {
        let parent = self.walk(parent_comps)?;
        if parent.kind != Kind::Dir {
            return Err(Error::NotADirectory(display_path(parent_comps)));
        }
        let mut entries = self.read_entries(&parent)?;
        let mut shown_parts = parent_comps.to_vec();
        shown_parts.push(name.to_string());
        let shown = display_path(&shown_parts);
        let now = now_unix();
        let file_len = data.len() as u64;
        let (created, old) = match entries.binary_search_by(|entry| entry.name.as_str().cmp(name)) {
            Ok(index) => {
                if Kind::from_u8(entries[index].kind)? != Kind::File {
                    return Err(type_change(&shown, Kind::Dir));
                }
                let old = self.load_inode(
                    entries[index].inode_block,
                    entries[index].inode_id,
                    &entries[index].chain_parity,
                )?;
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
            chain_parity: vec![0, 0, 0],
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
        self.write_content(&mut file_inode, data, PURPOSE_FILE)?;
        let (file_block, chain_parity) = self.store_inode(&file_inode)?;
        let entry = RawEntry {
            name: name.to_string(),
            inode_id: id,
            kind: KIND_FILE,
            inode_block: file_block,
            size: file_inode.size,
            chain_parity,
        };
        match entries.binary_search_by(|entry| entry.name.as_str().cmp(name)) {
            Ok(index) => entries[index] = entry,
            Err(index) => entries.insert(index, entry),
        }
        self.save_dir(parent_comps, parent, entries)?;
        if let Some(old) = old {
            self.free_content(&old)?;
            self.free_chain_blocks(old.stored_at, old.id, &old.chain_parity)?;
        }
        Ok(file_inode.size)
    }

    fn free_content(&mut self, inode: &Inode) -> Result<()> {
        for block in inode
            .content_blocks
            .iter()
            .chain(inode.content_parity.iter())
        {
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
        let child = self.load_inode(
            entries[index].inode_block,
            entries[index].inode_id,
            &entries[index].chain_parity,
        )?;
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
        self.free_chain_blocks(child.stored_at, child.id, &child.chain_parity)?;
        self.save_dir(parent_comps, parent, entries)
    }

    fn read_chain(&mut self, first: u64, inode_id: u64, parity: &[u64]) -> Result<ChainRead> {
        if parity.is_empty() || parity.len() % PARITY_COUNT as usize != 0 {
            return Err(Error::Corrupt("inode parity".into()));
        }
        let dek = self.dek_copy();
        let mut blocks = Vec::new();
        let mut plains = Vec::new();
        let mut bad = Vec::new();
        let mut next_block = first;
        loop {
            if blocks.contains(&next_block) || blocks.len() > 1024 {
                return Err(Error::Corrupt("inode chain".into()));
            }
            self.check_data_block(next_block)?;
            let logical = blocks.len() as u64;
            match self.read_sealed(next_block, &dek, PURPOSE_INODE, inode_id, logical, 0) {
                Ok(plain) => {
                    let (next, _) = split_chain(&plain)?;
                    blocks.push(next_block);
                    plains.push(plain.to_vec());
                    if next == CHAIN_END {
                        break;
                    }
                    next_block = next;
                }
                Err(Error::Corrupt(_)) if blocks.is_empty() => {
                    let rebuilt = self.rebuild_chain_head(first, inode_id, parity, &dek)?;
                    let (next, _) = split_chain(&rebuilt)?;
                    if next != CHAIN_END {
                        return Err(Error::Corrupt("inode chain".into()));
                    }
                    blocks.push(first);
                    plains.push(rebuilt);
                    bad.push(first);
                    break;
                }
                Err(Error::Corrupt(_)) => return Err(Error::Corrupt("inode chain".into())),
                Err(err) => return Err(err),
            }
        }
        if chain_parity_len(blocks.len() as u64) != parity.len() as u64 {
            return Err(Error::Corrupt("inode parity".into()));
        }
        let stripes = div_ceil(blocks.len() as u64, DATA_STRIPE) as usize;
        for stripe in 0..stripes {
            let begin = stripe * DATA_STRIPE as usize;
            let end = (begin + DATA_STRIPE as usize).min(plains.len());
            let refs: Vec<&[u8]> = plains[begin..end].iter().map(Vec::as_slice).collect();
            let expect = reed_solomon::encode(&refs)?;
            for index in 0..PARITY_COUNT as usize {
                let physical = parity[stripe * PARITY_COUNT as usize + index];
                self.check_data_block(physical)?;
                match self.read_sealed(
                    physical,
                    &dek,
                    PURPOSE_PARITY,
                    inode_id,
                    stripe as u64,
                    index as u32,
                ) {
                    Ok(plain) => {
                        if plain.as_ref() != expect[index].as_slice() {
                            return Err(Error::Corrupt("inode parity mismatch".into()));
                        }
                    }
                    Err(Error::Corrupt(_)) => bad.push(physical),
                    Err(err) => return Err(err),
                }
            }
        }
        if !bad.is_empty() {
            self.repair_hint = true;
        }
        let mut record = Vec::new();
        for plain in &plains {
            let (_, chunk) = split_chain(plain)?;
            record.extend_from_slice(chunk);
        }
        Ok(ChainRead { record, bad })
    }

    fn rebuild_chain_head(
        &mut self,
        physical: u64,
        inode_id: u64,
        parity: &[u64],
        dek: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let zeros = vec![0u8; PAYLOAD];
        let mut shards: [Option<Vec<u8>>; reed_solomon::STRIPE] = std::array::from_fn(|_| None);
        for index in 1..DATA_STRIPE as usize {
            shards[index] = Some(zeros.clone());
        }
        let mut survivors = 0usize;
        for index in 0..PARITY_COUNT as usize {
            match self.read_sealed(
                parity[index],
                dek,
                PURPOSE_PARITY,
                inode_id,
                0,
                index as u32,
            ) {
                Ok(plain) => {
                    shards[DATA_STRIPE as usize + index] = Some(plain.to_vec());
                    survivors += 1;
                }
                Err(Error::Corrupt(_)) => {}
                Err(err) => return Err(err),
            }
        }
        if survivors == 0 {
            return Err(Error::Corrupt("unrepairable inode".into()));
        }
        let view: [Option<&[u8]>; reed_solomon::STRIPE] =
            std::array::from_fn(|index| shards[index].as_deref());
        let rebuilt = reed_solomon::reconstruct(&view)?;
        let _ = physical;
        Ok(rebuilt[0].clone())
    }

    /// Data plains for one stripe. Missing blocks are rebuilt. Sets `repair_hint` when any member failed.
    fn read_content_stripe(
        &mut self,
        inode: &Inode,
        key: &[u8; 32],
        purpose: u8,
        data_at: usize,
        count: usize,
    ) -> Result<Vec<Vec<u8>>> {
        let stripe = data_at / DATA_STRIPE as usize;
        if inode.content_parity.len() < (stripe + 1) * PARITY_COUNT as usize {
            return Err(Error::Corrupt("content parity".into()));
        }
        let mut data: Vec<Option<Vec<u8>>> = Vec::with_capacity(count);
        let mut bad_data = 0usize;
        for offset in 0..count {
            let logical = (data_at + offset) as u64;
            let physical = inode.content_blocks[data_at + offset];
            match self.read_sealed(physical, key, purpose, inode.id, logical, 0) {
                Ok(plain) => data.push(Some(plain.to_vec())),
                Err(Error::Corrupt(_)) => {
                    bad_data += 1;
                    data.push(None);
                }
                Err(err) => return Err(err),
            }
        }
        let mut parity: Vec<Option<Vec<u8>>> = Vec::with_capacity(PARITY_COUNT as usize);
        let mut bad_parity = 0usize;
        for index in 0..PARITY_COUNT as usize {
            let physical = inode.content_parity[stripe * PARITY_COUNT as usize + index];
            match self.read_sealed(
                physical,
                key,
                PURPOSE_PARITY,
                inode.id,
                stripe as u64,
                index as u32,
            ) {
                Ok(plain) => parity.push(Some(plain.to_vec())),
                Err(Error::Corrupt(_)) => {
                    bad_parity += 1;
                    parity.push(None);
                }
                Err(err) => return Err(err),
            }
        }
        if bad_data + bad_parity > PARITY_COUNT as usize {
            return Err(Error::Corrupt("unrepairable stripe".into()));
        }
        if bad_data == 0 && bad_parity == 0 {
            let got: Vec<Vec<u8>> = data.into_iter().map(|plain| plain.unwrap()).collect();
            let refs: Vec<&[u8]> = got.iter().map(Vec::as_slice).collect();
            let expect = reed_solomon::encode(&refs)?;
            for (index, plain) in parity.iter().enumerate() {
                if plain.as_ref().map(Vec::as_slice) != Some(expect[index].as_slice()) {
                    return Err(Error::Corrupt("parity mismatch".into()));
                }
            }
            return Ok(got);
        }
        self.repair_hint = true;
        if bad_data == 0 {
            return Ok(data.into_iter().map(|plain| plain.unwrap()).collect());
        }
        let zeros = vec![0u8; PAYLOAD];
        let mut shards: [Option<Vec<u8>>; reed_solomon::STRIPE] = std::array::from_fn(|_| None);
        for index in 0..DATA_STRIPE as usize {
            if index < count {
                shards[index] = data[index].clone();
            } else {
                shards[index] = Some(zeros.clone());
            }
        }
        for index in 0..PARITY_COUNT as usize {
            shards[DATA_STRIPE as usize + index] = parity[index].clone();
        }
        let view: [Option<&[u8]>; reed_solomon::STRIPE] =
            std::array::from_fn(|index| shards[index].as_deref());
        let rebuilt = reed_solomon::reconstruct(&view)?;
        Ok(rebuilt.into_iter().take(count).collect())
    }

    fn repair_path(&mut self, comps: &[String]) -> Result<()> {
        for depth in 0..=comps.len() {
            self.repair_at(&comps[..depth])?;
        }
        Ok(())
    }

    /// Rewrites damaged stripes of one inode. The caller holds the transaction.
    fn repair_at(&mut self, comps: &[String]) -> Result<u64> {
        let mut inode = self.walk(comps)?;
        let purpose = match inode.kind {
            Kind::Dir => PURPOSE_DIR,
            Kind::File => PURPOSE_FILE,
        };
        let content_bad = self.rewrite_bad_content(&mut inode, purpose)?;
        let chain = self.read_chain(inode.stored_at, inode.id, &inode.chain_parity)?;
        if content_bad == 0 && chain.bad.is_empty() {
            return Ok(0);
        }
        let chain_bad = chain.bad.len() as u64;
        self.publish_inode(&inode, comps)?;
        Ok(content_bad + chain_bad)
    }

    fn rewrite_bad_content(&mut self, inode: &mut Inode, purpose: u8) -> Result<u64> {
        if inode.content_blocks.is_empty() {
            return Ok(0);
        }
        let key = inode.file_key.clone();
        let id = inode.id;
        let mut repaired = 0u64;
        let mut index = 0usize;
        while index < inode.content_blocks.len() {
            let count = (inode.content_blocks.len() - index).min(DATA_STRIPE as usize);
            let stripe = index / DATA_STRIPE as usize;
            let before = self.repair_hint;
            self.repair_hint = false;
            let plains = self.read_content_stripe(inode, &key, purpose, index, count)?;
            let damaged = self.repair_hint;
            self.repair_hint = before || damaged;
            if !damaged {
                index += count;
                continue;
            }
            let parity_plain = {
                let refs: Vec<&[u8]> = plains.iter().map(Vec::as_slice).collect();
                reed_solomon::encode(&refs)?
            };
            let mut members: Vec<u64> = inode.content_blocks[index..index + count].to_vec();
            members.extend_from_slice(
                &inode.content_parity
                    [stripe * PARITY_COUNT as usize..(stripe + 1) * PARITY_COUNT as usize],
            );
            for offset in 0..count {
                let logical = (index + offset) as u64;
                let physical = inode.content_blocks[index + offset];
                if self
                    .read_sealed(physical, &key, purpose, id, logical, 0)
                    .is_ok()
                {
                    continue;
                }
                let new_block = self.alloc_block_away(&members)?;
                self.write_sealed(new_block, &plains[offset], &key, purpose, id, logical, 0)?;
                self.free_block(physical)?;
                if let Some(pos) = members.iter().position(|block| *block == physical) {
                    members[pos] = new_block;
                }
                inode.content_blocks[index + offset] = new_block;
                repaired += 1;
            }
            for parity_index in 0..PARITY_COUNT as usize {
                let slot = stripe * PARITY_COUNT as usize + parity_index;
                let physical = inode.content_parity[slot];
                if self
                    .read_sealed(
                        physical,
                        &key,
                        PURPOSE_PARITY,
                        id,
                        stripe as u64,
                        parity_index as u32,
                    )
                    .is_ok()
                {
                    continue;
                }
                let new_block = self.alloc_block_away(&members)?;
                self.write_sealed(
                    new_block,
                    &parity_plain[parity_index],
                    &key,
                    PURPOSE_PARITY,
                    id,
                    stripe as u64,
                    parity_index as u32,
                )?;
                self.free_block(physical)?;
                if let Some(pos) = members.iter().position(|block| *block == physical) {
                    members[pos] = new_block;
                }
                inode.content_parity[slot] = new_block;
                repaired += 1;
            }
            index += count;
        }
        Ok(repaired)
    }

    fn publish_inode(&mut self, inode: &Inode, comps: &[String]) -> Result<()> {
        let old = inode.stored_at;
        let old_parity = inode.chain_parity.clone();
        let (block, parity) = self.store_inode(inode)?;
        self.free_chain_blocks(old, inode.id, &old_parity)?;
        if comps.is_empty() {
            self.root_inode_block = block;
            self.root_parity = parity3(&parity)?;
            return Ok(());
        }
        let parent_comps = &comps[..comps.len() - 1];
        let name = comps[comps.len() - 1].clone();
        let parent = self.walk(parent_comps)?;
        let mut entries = self.read_entries(&parent)?;
        match entries.iter_mut().find(|entry| entry.name == name) {
            Some(entry) => {
                entry.inode_block = block;
                entry.chain_parity = parity;
                entry.inode_id = inode.id;
                entry.kind = inode.kind.as_u8();
                entry.size = if inode.kind == Kind::File {
                    inode.size
                } else {
                    0
                };
            }
            None => return Err(Error::Corrupt(format!("missing directory entry {name}"))),
        }
        self.save_dir(parent_comps, parent, entries)
    }
}

struct ChainRead {
    record: Vec<u8>,
    bad: Vec<u64>,
}

struct Candidate {
    index: usize,
    header: SuperHeader,
    dek: Zeroizing<[u8; 32]>,
    body: SuperBody,
    kdf: KdfParams,
}

fn blocks_for(content_blocks: u64) -> u64 {
    let chain = inode_chain_blocks(content_blocks);
    content_blocks + content_parity_len(content_blocks) + chain + chain_parity_len(chain)
}

fn parity3(blocks: &[u64]) -> Result<[u64; 3]> {
    if blocks.len() != PARITY_COUNT as usize {
        return Err(Error::Corrupt("root parity".into()));
    }
    Ok([blocks[0], blocks[1], blocks[2]])
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
        parity: inode.content_parity.clone(),
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

fn is_open_volume(file: &File, dest: &Path) -> bool {
    if let (Ok(open_meta), Ok(dest_meta)) = (file.metadata(), std::fs::metadata(dest)) {
        if open_meta.dev() == dest_meta.dev() && open_meta.ino() == dest_meta.ino() {
            return true;
        }
    }
    let Ok(open_path) = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())) else {
        return false;
    };
    paths_match(&open_path, dest)
}

fn paths_match(open_path: &Path, dest: &Path) -> bool {
    let Ok(open_canon) = std::fs::canonicalize(open_path) else {
        return false;
    };
    if let Ok(dest_canon) = std::fs::canonicalize(dest) {
        return open_canon == dest_canon;
    }
    let Some(name) = dest.file_name() else {
        return false;
    };
    let parent = match dest.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Ok(parent_canon) = std::fs::canonicalize(parent) else {
        return false;
    };
    parent_canon.join(name) == open_canon
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
    let start = u64::from(slot) * slot_span(blocks);
    let mut plains = Vec::with_capacity(blocks as usize);
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
        plains.push(plain);
    }
    let mut stripe = 0u64;
    while stripe * DATA_STRIPE < blocks {
        let begin = (stripe * DATA_STRIPE) as usize;
        let end = ((stripe + 1) * DATA_STRIPE).min(blocks) as usize;
        let refs: Vec<&[u8]> = plains[begin..end].iter().map(Vec::as_slice).collect();
        let parity = reed_solomon::encode(&refs)?;
        for (index, plain) in parity.iter().enumerate() {
            let physical = start + blocks + stripe * PARITY_COUNT + index as u64;
            write_sealed_at(
                file,
                total_physical,
                physical,
                plain,
                dek,
                volume_id,
                PURPOSE_PARITY,
                0,
                stripe,
                index as u32,
            )?;
        }
        stripe += 1;
    }
    for plain in &mut plains {
        plain.zeroize();
    }
    Ok(())
}

fn chain_plain(next: u64, chunk: &[u8]) -> Vec<u8> {
    let mut plain = vec![0u8; PAYLOAD];
    plain[0..8].copy_from_slice(&next.to_le_bytes());
    plain[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    plain[12..12 + chunk.len()].copy_from_slice(chunk);
    plain
}

fn chain_plains(blocks: &[u64], record: &[u8]) -> Result<Vec<Vec<u8>>> {
    let cap = PAYLOAD - 12;
    let chunks: Vec<&[u8]> = if record.is_empty() {
        vec![b""]
    } else {
        record.chunks(cap).collect()
    };
    if chunks.len() != blocks.len() {
        return Err(Error::Corrupt("inode chain allocation".into()));
    }
    let mut plains = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let next = if index + 1 == chunks.len() {
            CHAIN_END
        } else {
            blocks[index + 1]
        };
        plains.push(chain_plain(next, chunk));
    }
    Ok(plains)
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthReport {
    pub checked_blocks: u64,
    pub repaired_blocks: u64,
    pub unrepairable: u64,
}

impl Volume {
    /// Checks every stripe and rewrites blocks that fail authentication.
    /// A stripe with more than three bad blocks is counted and left unchanged.
    /// `progress` is `stage, completed units, total units`. An error stops the scan.
    pub fn health(
        &mut self,
        progress: &mut dyn FnMut(&str, u64, u64) -> Result<()>,
    ) -> Result<HealthReport> {
        if !self.exclusive {
            return Err(Error::Denied("volume is open read-only".into()));
        }
        // Cached directory and inode plaintext would hide damage that landed after the read.
        self.block_cache.clear();
        let total = match self.count_work() {
            Ok(count) => count.max(1),
            Err(Error::Corrupt(_)) => self.used_blocks.max(1),
            Err(err) => return Err(err),
        };
        let mut report = HealthReport {
            checked_blocks: 0,
            repaired_blocks: 0,
            unrepairable: 0,
        };
        let mut done = 0u64;
        progress("bitmap", done, total)?;
        let bitmap_blocks = u64::from(self.bitmap_blocks_per_slot);
        report.checked_blocks += bitmap_blocks + bitmap_parity_blocks(bitmap_blocks);
        match self.heal_bitmap() {
            Ok(repaired) => report.repaired_blocks += repaired,
            Err(Error::Corrupt(_)) => report.unrepairable += 1,
            Err(err) => return Err(err),
        }
        done += 1;
        self.health_walk(&[], &mut report, &mut done, total, progress)?;
        Ok(report)
    }

    fn heal_bitmap(&mut self) -> Result<u64> {
        let bad = self.audit_bitmap()?;
        if bad == 0 {
            self.bitmap_needs_heal = false;
            return Ok(0);
        }
        self.with_txn(|_| Ok(()))?;
        self.bitmap_needs_heal = false;
        Ok(bad)
    }

    fn audit_bitmap(&mut self) -> Result<u64> {
        let blocks = u64::from(self.bitmap_blocks_per_slot);
        let start = self.slot_base(self.bitmap_slot);
        let dek = self.dek_copy();
        let mut bad = 0u64;
        let mut plains = Vec::with_capacity(blocks as usize);
        let mut missing = false;
        for index in 0..blocks {
            match self.read_sealed(
                start + index,
                &dek,
                PURPOSE_BITMAP,
                0,
                index,
                self.bitmap_slot,
            ) {
                Ok(plain) => plains.push(Some(plain)),
                Err(Error::Corrupt(_)) => {
                    bad += 1;
                    missing = true;
                    plains.push(None);
                }
                Err(err) => return Err(err),
            }
        }
        let parity_blocks = bitmap_parity_blocks(blocks);
        for index in 0..parity_blocks {
            let stripe = index / PARITY_COUNT;
            let extra = (index % PARITY_COUNT) as u32;
            match self.read_sealed(
                start + blocks + index,
                &dek,
                PURPOSE_PARITY,
                0,
                stripe,
                extra,
            ) {
                Ok(_) => {}
                Err(Error::Corrupt(_)) => bad += 1,
                Err(err) => return Err(err),
            }
        }
        if missing {
            self.reconstruct_bitmap(start, &mut plains)?;
        }
        Ok(bad)
    }

    fn count_work(&mut self) -> Result<u64> {
        let mut count = 1u64;
        self.count_at(&[], &mut count)?;
        Ok(count)
    }

    fn count_at(&mut self, comps: &[String], count: &mut u64) -> Result<()> {
        let inode = self.walk(comps)?;
        *count += 1;
        if !inode.content_blocks.is_empty() {
            *count += div_ceil(inode.content_blocks.len() as u64, DATA_STRIPE);
        }
        if inode.kind != Kind::Dir {
            return Ok(());
        }
        for entry in self.read_entries(&inode)? {
            let mut child = comps.to_vec();
            child.push(entry.name);
            self.count_at(&child, count)?;
        }
        Ok(())
    }

    fn health_walk(
        &mut self,
        comps: &[String],
        report: &mut HealthReport,
        done: &mut u64,
        total: u64,
        progress: &mut dyn FnMut(&str, u64, u64) -> Result<()>,
    ) -> Result<()> {
        let label = if comps.is_empty() {
            "/".to_string()
        } else {
            display_path(comps)
        };
        progress(&label, *done, total)?;
        let inode = match self.walk(comps) {
            Ok(inode) => inode,
            Err(Error::Corrupt(_)) => {
                report.unrepairable += 1;
                *done += 1;
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        report.checked_blocks += 1 + inode.chain_parity.len() as u64;
        report.checked_blocks +=
            inode.content_blocks.len() as u64 + inode.content_parity.len() as u64;
        let damaged = match self.inode_damaged(&inode, &label, done, total, progress) {
            Ok(damaged) => damaged,
            Err(Error::Corrupt(_)) => {
                report.unrepairable += 1;
                *done += 1;
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        let mut inode = inode;
        if damaged || (comps.is_empty() && self.bitmap_needs_heal) {
            match self.with_txn(|vol| vol.repair_at(comps)) {
                Ok(repaired) => report.repaired_blocks += repaired,
                Err(Error::Corrupt(_)) => {
                    report.unrepairable += 1;
                    *done += 1;
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
            inode = match self.walk(comps) {
                Ok(inode) => inode,
                Err(Error::Corrupt(_)) => {
                    report.unrepairable += 1;
                    *done += 1;
                    return Ok(());
                }
                Err(err) => return Err(err),
            };
        }
        *done += 1;
        if inode.kind != Kind::Dir {
            return Ok(());
        }
        let entries = match self.read_entries(&inode) {
            Ok(entries) => entries,
            Err(Error::Corrupt(_)) => {
                report.unrepairable += 1;
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        for entry in entries {
            let mut child = comps.to_vec();
            child.push(entry.name);
            self.health_walk(&child, report, done, total, progress)?;
        }
        Ok(())
    }

    fn inode_damaged(
        &mut self,
        inode: &Inode,
        label: &str,
        done: &mut u64,
        total: u64,
        progress: &mut dyn FnMut(&str, u64, u64) -> Result<()>,
    ) -> Result<bool> {
        let chain = self.read_chain(inode.stored_at, inode.id, &inode.chain_parity)?;
        if !chain.bad.is_empty() {
            return Ok(true);
        }
        let purpose = match inode.kind {
            Kind::Dir => PURPOSE_DIR,
            Kind::File => PURPOSE_FILE,
        };
        let key = inode.file_key.clone();
        let mut index = 0usize;
        let mut damaged = false;
        while index < inode.content_blocks.len() {
            progress(label, *done, total)?;
            let count = (inode.content_blocks.len() - index).min(DATA_STRIPE as usize);
            let saved = self.repair_hint;
            self.repair_hint = false;
            let _plains = self.read_content_stripe(inode, &key, purpose, index, count)?;
            damaged |= self.repair_hint;
            self.repair_hint = saved || damaged;
            index += count;
            *done += 1;
        }
        Ok(damaged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::block_offset;

    #[path = "fault_tests.rs"]
    mod fault_tests;

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
            size: Some(128 * 1024 * 1024),
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

    #[test]
    fn backup_copies_the_addressable_image_and_refuses_the_open_volume() {
        use std::os::unix::fs::PermissionsExt;

        let size = crate::format::minimum_volume_bytes() + 100;
        let path = tmp("backup");
        init_volume(InitOptions {
            path: &path.0,
            password: PASSWORD,
            size: Some(size),
            force: false,
            kdf: kdf(),
            progress: None,
        })
        .unwrap();
        let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
        let Stat::Volume { size: image, .. } = volume.stat(None).unwrap() else {
            panic!("volume stat");
        };
        assert!(image < size);
        assert_eq!(image, HEADER_BYTES + volume.total_physical * BLOCK_SIZE);

        let err = volume
            .backup(Path::new(""), &mut |_, _| Ok(()))
            .unwrap_err();
        assert_eq!(err.to_string(), "empty input");

        let dir = tmp("backup-dir");
        std::fs::create_dir(&dir.0).unwrap();
        let err = volume.backup(&dir.0, &mut |_, _| Ok(())).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{} is a directory", dir.0.display())
        );
        let _ = std::fs::remove_dir(&dir.0);

        let err = volume.backup(&path.0, &mut |_, _| Ok(())).unwrap_err();
        assert_eq!(err.to_string(), "backup path is the open volume");
        let link = tmp("backup-link");
        std::os::unix::fs::symlink(&path.0, &link.0).unwrap();
        let err = volume.backup(&link.0, &mut |_, _| Ok(())).unwrap_err();
        assert_eq!(err.to_string(), "backup path is the open volume");
        let _ = std::fs::remove_file(&link.0);

        let out = tmp("backup-out");
        std::fs::create_dir(&out.0).unwrap();
        let dest = out.0.join("copy.img");
        std::fs::write(&dest, b"keep").unwrap();
        let err = volume
            .backup(&dest, &mut |done, _| {
                if done > 0 {
                    Err(Error::Message("stop".into()))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(err.to_string(), "stop");
        assert_eq!(std::fs::read(&dest).unwrap(), b"keep");
        let names: Vec<_> = std::fs::read_dir(&out.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|name| !name.contains(".hdnfs-partial-")),
            "{names:?}"
        );

        let mut seen = Vec::new();
        let bytes = volume
            .backup(&dest, &mut |done, total| {
                seen.push((done, total));
                Ok(())
            })
            .unwrap();
        assert_eq!(bytes, image);
        assert_eq!(seen.first(), Some(&(0, image)));
        assert_eq!(seen.last(), Some(&(image, image)));
        assert_eq!(std::fs::metadata(&dest).unwrap().len(), image);
        assert!(std::fs::metadata(&path.0).unwrap().len() > image);
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut prefix = vec![0u8; image as usize];
        File::open(&path.0)
            .unwrap()
            .read_exact(&mut prefix)
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), prefix);
        assert_eq!(&prefix[..8], &MAGIC[..]);

        let mut copy = Volume::open(&dest, PASSWORD, LockMode::Shared).unwrap();
        let Stat::Volume {
            size: copy_size, ..
        } = copy.stat(None).unwrap()
        else {
            panic!("backup stat");
        };
        assert_eq!(copy_size, image);
        drop(copy);
        drop(volume);

        let mut shared = Volume::open(&path.0, PASSWORD, LockMode::Shared).unwrap();
        let err = shared.backup(&dest, &mut |_, _| Ok(())).unwrap_err();
        assert_eq!(err.to_string(), "volume is open read-only");
        let _ = std::fs::remove_dir_all(&out.0);
    }

    /// Writes the backup image back onto the start of a volume file.
    fn restore_image(backup: &Path, volume: &Path) {
        let mut src = File::open(backup).unwrap();
        let mut dest = OpenOptions::new().write(true).open(volume).unwrap();
        let mut buf = vec![0u8; BLOCK_SIZE as usize];
        loop {
            let n = src.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            dest.write_all(&buf[..n]).unwrap();
        }
        dest.sync_all().unwrap();
    }

    #[test]
    fn backup_and_restore_roundtrip_files() {
        let size = 64 * 1024 * 1024;
        let path = tmp("backup-restore");
        init_volume(InitOptions {
            path: &path.0,
            password: PASSWORD,
            size: Some(size),
            force: false,
            kdf: kdf(),
            progress: None,
        })
        .unwrap();
        let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
        let note = b"the note survives backup and restore";
        volume.write_bytes("/docs/note.txt", note).unwrap();
        volume
            .write_bytes("/docs/other.txt", b"second file")
            .unwrap();
        let Stat::Volume { size: image, .. } = volume.stat(None).unwrap() else {
            panic!("volume stat");
        };
        assert!(std::fs::metadata(&path.0).unwrap().len() > image);

        let out = tmp("backup-restore-out");
        std::fs::create_dir(&out.0).unwrap();
        let dest = out.0.join("copy.img");
        let bytes = volume.backup(&dest, &mut |_, _| Ok(())).unwrap();
        assert_eq!(bytes, image);
        drop(volume);

        let restored_path = out.0.join("restored.img");
        let mut saved = Volume::open(&dest, PASSWORD, LockMode::Exclusive).unwrap();
        assert_eq!(&saved.read_bytes("/docs/note.txt").unwrap()[..], note);
        assert_eq!(
            &saved.read_bytes("/docs/other.txt").unwrap()[..],
            b"second file"
        );
        let restored_bytes = saved.backup(&restored_path, &mut |_, _| Ok(())).unwrap();
        assert_eq!(restored_bytes, image);
        drop(saved);
        let mut via_backup = Volume::open(&restored_path, PASSWORD, LockMode::Shared).unwrap();
        assert_eq!(&via_backup.read_bytes("/docs/note.txt").unwrap()[..], note);
        assert_eq!(
            &via_backup.read_bytes("/docs/other.txt").unwrap()[..],
            b"second file"
        );
        drop(via_backup);

        {
            let mut file = OpenOptions::new().write(true).open(&path.0).unwrap();
            let zeros = vec![0u8; BLOCK_SIZE as usize];
            let mut left = image;
            while left > 0 {
                let n = usize::try_from(left.min(BLOCK_SIZE)).unwrap();
                file.write_all(&zeros[..n]).unwrap();
                left -= n as u64;
            }
            file.sync_all().unwrap();
        }
        assert!(Volume::open(&path.0, PASSWORD, LockMode::Shared).is_err());

        restore_image(&dest, &path.0);

        let mut restored = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
        assert_eq!(&restored.read_bytes("/docs/note.txt").unwrap()[..], note);
        assert_eq!(
            &restored.read_bytes("/docs/other.txt").unwrap()[..],
            b"second file"
        );
        let Stat::Volume {
            size: restored_size,
            ..
        } = restored.stat(None).unwrap()
        else {
            panic!("restored stat");
        };
        assert_eq!(restored_size, image);
        assert_eq!(std::fs::metadata(&path.0).unwrap().len(), size);
        let _ = std::fs::remove_dir_all(&out.0);
    }

    #[test]
    fn write_bytes_roundtrip_replaces_a_file() {
        let path = tmp("bytes");
        init_volume(InitOptions {
            path: &path.0,
            password: PASSWORD,
            size: Some(128 * 1024 * 1024),
            force: false,
            kdf: kdf(),
            progress: None,
        })
        .unwrap();
        let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
        volume
            .write_bytes("/ssh/keys/laptop/private", b"one")
            .unwrap();
        assert_eq!(
            &volume.read_bytes("/ssh/keys/laptop/private").unwrap()[..],
            b"one"
        );
        let names: Vec<_> = volume
            .list("/")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert!(names.contains(&"ssh".to_string()));
        volume
            .write_bytes("/ssh/keys/laptop/private", b"two")
            .unwrap();
        assert_eq!(
            &volume.read_bytes("/ssh/keys/laptop/private").unwrap()[..],
            b"two"
        );
        let stat = volume.stat(Some("/ssh/keys/laptop/private")).unwrap();
        assert!(matches!(
            stat,
            Stat::Node {
                kind: Kind::File,
                size: 3,
                ..
            }
        ));
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
        let first = volume.alloc_block_away(&[]).unwrap();
        let snap = volume.snapshot().unwrap();
        let second = volume.alloc_block_away(&[]).unwrap();
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
            let (data, parity) = volume.testing_stripe("/a").unwrap();
            assert_eq!(data.len(), 1);
            assert_eq!(parity.len(), 3);
            let original = data[0];
            volume.testing_poke(block_offset(original) + 80).unwrap();
            let out = tmp("repaired");
            let generation = volume.generation;
            volume.get("/a", &out.0).unwrap();
            assert_eq!(std::fs::read(&out.0).unwrap(), b"authenticated");
            assert!(volume.generation > generation);
            let (data, _) = volume.testing_stripe("/a").unwrap();
            assert_ne!(data[0], original);
            volume.testing_poke(block_offset(data[0]) + 80).unwrap();
            for block in &parity {
                volume.testing_poke(block_offset(*block) + 80).unwrap();
            }
            let err = volume.get("/a", &tmp("dead").0).unwrap_err();
            assert_eq!(err.code(), "corrupt");
        }
        match Volume::open(&path.0, "another password!!", LockMode::Shared) {
            Err(err) => assert_eq!(err.code(), "wrong_password"),
            Ok(_) => panic!("wrong password opened the volume"),
        }
        {
            let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
            volume.testing_poke(300).unwrap();
            volume.testing_poke(4096 + 300).unwrap();
        }
        Volume::open(&path.0, PASSWORD, LockMode::Shared).unwrap();
        {
            // Copies 0 and 1 are already damaged. Poking them again would restore them.
            let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
            volume.testing_poke(8192 + 300).unwrap();
        }
        match Volume::open(&path.0, PASSWORD, LockMode::Shared) {
            Err(err) => assert_eq!(err.code(), "corrupt"),
            Ok(_) => panic!("damaged headers still opened"),
        }
    }

    #[test]
    fn health_repairs_one_block_and_counts_an_unrepairable_stripe() {
        let path = tmp("health");
        init_at(&path.0, PASSWORD, false).unwrap();
        let mut volume = Volume::open(&path.0, PASSWORD, LockMode::Exclusive).unwrap();
        let source = host_file("body", b"healthy-bytes");
        volume.put(&source.0, "/note").unwrap();
        let generation = volume.generation;
        let clean = volume.health(&mut |_, _, _| Ok(())).unwrap();
        assert_eq!(clean.repaired_blocks, 0);
        assert_eq!(clean.unrepairable, 0);
        assert!(clean.checked_blocks > 0);
        assert_eq!(volume.generation, generation);

        let (_data, parity) = volume.testing_stripe("/note").unwrap();
        volume.testing_poke(block_offset(parity[1]) + 40).unwrap();
        let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
        assert!(report.repaired_blocks >= 1);
        assert_eq!(report.unrepairable, 0);
        let out = tmp("note-out");
        volume.get("/note", &out.0).unwrap();
        assert_eq!(std::fs::read(&out.0).unwrap(), b"healthy-bytes");

        let (data, parity) = volume.testing_stripe("/note").unwrap();
        volume.testing_poke(block_offset(data[0]) + 10).unwrap();
        for block in &parity {
            volume.testing_poke(block_offset(*block) + 10).unwrap();
        }
        let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
        assert!(report.unrepairable >= 1);
        let err = volume.get("/note", &tmp("gone").0).unwrap_err();
        assert_eq!(err.code(), "corrupt");
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
                assert_eq!(used_blocks, 4);
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

        fn testing_stripe(&mut self, path: &str) -> Result<(Vec<u64>, Vec<u64>)> {
            let parsed = parse_path(path)?;
            let inode = self.walk(&parsed.components)?;
            Ok((inode.content_blocks, inode.content_parity))
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
