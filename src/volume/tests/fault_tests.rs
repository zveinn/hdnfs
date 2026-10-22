//! Fault injection on a small prefix of the test SSD.
//!
//! Every test serializes on one mutex, checks that `/dev/sda` is the unmounted
//! PS8, and passes an explicit size. A full-disk init is never requested.
//! Markers past the prefix must still be there when the test finishes.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use super::super::{
    block_device_bytes, has_volume_magic, init_volume, read_exact_at, write_exact_at, InitOptions,
    Kind, LockMode, Stat, Volume,
};
use super::{kdf, PASSWORD};
use crate::error::Error;
use crate::format::{
    block_offset, minimum_volume_bytes, BLOCK_SIZE, HEADER_BYTES, PAYLOAD, PURPOSE_DIR,
    PURPOSE_FILE, PURPOSE_INODE, PURPOSE_PARITY, SUPER_SIZE,
};
use crate::pathutil::parse_path;

const DEVICE: &str = "/dev/sda";
const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
const WIDE_BYTES: u64 = 96 * 1024 * 1024;
/// Deep directories rewrite every ancestor in one transaction.
const ROOMY_BYTES: u64 = 128 * 1024 * 1024;
const MARKER: &[u8; 16] = b"HDNFS-MARK-KEEP!";
const MARK_MID: u64 = 256 * 1024 * 1024;
const MARK_FAR: u64 = 1024 * 1024 * 1024;
const POKE_AT: u64 = 80;

static DRIVE: Mutex<()> = Mutex::new(());
static MARKERS_ARMED: AtomicBool = AtomicBool::new(false);

struct DriveGuard {
    _lock: MutexGuard<'static, ()>,
    /// First byte past the prefix this test initialized. Zero before init.
    fence: u64,
}

impl Drop for DriveGuard {
    fn drop(&mut self) {
        if std::thread::panicking() || !MARKERS_ARMED.load(Ordering::SeqCst) {
            return;
        }
        assert_markers();
        if self.fence != 0 {
            assert_eq!(
                read_raw(self.fence, MARKER.len()),
                MARKER,
                "init wrote past the requested {}-byte prefix",
                self.fence
            );
        }
    }
}

fn claim() -> DriveGuard {
    let lock = match DRIVE.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_test_drive();
    DriveGuard {
        _lock: lock,
        fence: 0,
    }
}

fn assert_test_drive() {
    let path = Path::new(DEVICE);
    let meta = std::fs::metadata(path).unwrap_or_else(|err| {
        panic!("refusing to test: cannot stat {DEVICE}: {err}");
    });
    assert!(
        meta.file_type().is_block_device(),
        "refusing to test: {DEVICE} is not a block device"
    );
    let model = std::fs::read_to_string("/sys/block/sda/device/model")
        .unwrap_or_else(|err| panic!("refusing to test: cannot read the sda model: {err}"));
    assert!(
        model.contains("PS8") && model.contains("SSD"),
        "refusing to test: /dev/sda model is {model:?}, want the PS8 Portable SSD"
    );
    let sectors: u64 = std::fs::read_to_string("/sys/block/sda/size")
        .unwrap_or_else(|err| panic!("refusing to test: cannot read /sys/block/sda/size: {err}"))
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("refusing to test: sda size is not a number"));
    let bytes = sectors.saturating_mul(512);
    assert!(
        bytes > 400 * 1024 * 1024 * 1024 && bytes > MARK_FAR + MARKER.len() as u64,
        "refusing to test: /dev/sda is only {bytes} bytes"
    );
    for entry in std::fs::read_dir("/sys/block/sda")
        .unwrap_or_else(|err| panic!("refusing to test: cannot list /sys/block/sda: {err}"))
    {
        let name = entry
            .unwrap_or_else(|err| panic!("refusing to test: {err}"))
            .file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.starts_with("sda"),
            "refusing to test: /dev/sda has partition {name}"
        );
    }
    let holders = std::fs::read_dir("/sys/block/sda/holders")
        .unwrap_or_else(|err| panic!("refusing to test: cannot list holders: {err}"));
    let held: Vec<_> = holders
        .map(|entry| {
            entry
                .unwrap_or_else(|err| panic!("refusing to test: {err}"))
                .file_name()
        })
        .collect();
    assert!(
        held.is_empty(),
        "refusing to test: /dev/sda is held by {held:?}"
    );
    let mounts = std::fs::read_to_string("/proc/mounts")
        .unwrap_or_else(|err| panic!("refusing to test: cannot read mounts: {err}"));
    let mut root = None;
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let Some(source) = parts.next() else { continue };
        let Some(target) = parts.next() else { continue };
        assert!(
            !source.starts_with("/dev/sda"),
            "refusing to test: {source} is mounted on {target}"
        );
        if target == "/" {
            root = Some(source.to_string());
        }
    }
    let root = root.unwrap_or_else(|| panic!("refusing to test: no root mount"));
    assert!(
        root.contains("nvme") && !root.contains("sda"),
        "refusing to test: root is {root}"
    );
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap_or_else(|err| panic!("refusing to test: cannot open {DEVICE} read-write: {err}"));
    let device = block_device_bytes(path).unwrap_or_else(|err| {
        panic!("refusing to test: cannot read the block device size: {err}");
    });
    assert!(
        device > 400 * 1024 * 1024 * 1024 && device > MARK_FAR,
        "refusing to test: block device size is {device}"
    );
}

fn write_raw(offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEVICE)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn read_raw(offset: u64, len: usize) -> Vec<u8> {
    let mut file = File::open(DEVICE).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).unwrap();
    buf
}

fn arm_markers() {
    if MARKERS_ARMED.load(Ordering::SeqCst) {
        assert_markers();
    }
    write_raw(MARK_MID, MARKER);
    write_raw(MARK_FAR, MARKER);
    MARKERS_ARMED.store(true, Ordering::SeqCst);
}

fn assert_markers() {
    assert_eq!(read_raw(MARK_MID, MARKER.len()), MARKER, "256 MiB marker");
    assert_eq!(read_raw(MARK_FAR, MARKER.len()), MARKER, "1 GiB marker");
}

fn expected_addressable(size: u64) -> u64 {
    let blocks = (size - HEADER_BYTES) / BLOCK_SIZE;
    HEADER_BYTES + blocks * BLOCK_SIZE
}

fn init_prefix(guard: &mut DriveGuard, size: u64) -> u64 {
    arm_markers();
    write_raw(size, MARKER);
    guard.fence = size;
    let addressable = init_volume(InitOptions {
        path: Path::new(DEVICE),
        password: PASSWORD,
        size: Some(size),
        force: true,
        kdf: kdf(),
        progress: None,
    })
    .unwrap_or_else(|err| panic!("init of {size} bytes failed: {err}"));
    assert_markers();
    assert_eq!(read_raw(size, MARKER.len()), MARKER);
    let expect = expected_addressable(size);
    assert_eq!(addressable, expect);
    assert!(addressable <= size);
    assert!(size - addressable < BLOCK_SIZE);
    addressable
}

fn open_exclusive() -> Volume {
    Volume::open(Path::new(DEVICE), PASSWORD, LockMode::Exclusive)
        .unwrap_or_else(|err| panic!("open failed: {err}"))
}

fn setup(guard: &mut DriveGuard, size: u64) -> Volume {
    let addressable = init_prefix(guard, size);
    let mut volume = open_exclusive();
    match volume.stat(None).unwrap() {
        Stat::Volume {
            size: got,
            used_blocks,
            ..
        } => {
            assert_eq!(got, addressable);
            assert_eq!(used_blocks, 4);
        }
        Stat::Node { .. } => panic!("expected a volume stat"),
    }
    assert!(has_volume_magic(Path::new(DEVICE)).unwrap());
    volume
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn scratch(label: &str) -> Scratch {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("hdnfs-fault-{label}-{}-{n}", std::process::id()));
    Scratch(path)
}

fn host_bytes(label: &str, bytes: &[u8]) -> Scratch {
    let file = scratch(label);
    std::fs::write(&file.0, bytes).unwrap();
    file
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = u32::from(seed) | 1;
    for _ in 0..len {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        out.push((state >> 24) as u8);
    }
    out
}

fn choose(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn rec(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for index in start..n {
            cur.push(index);
            rec(index + 1, n, k, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    if k <= n {
        rec(0, n, k, &mut Vec::new(), &mut out);
    }
    out
}

fn stripe_members(volume: &mut Volume, path: &str, stripe: usize) -> Vec<u64> {
    let (data, parity) = volume.testing_stripe(path).unwrap();
    let begin = stripe * 8;
    let end = (begin + 8).min(data.len());
    let mut members = data[begin..end].to_vec();
    let parity_at = stripe * 3;
    members.extend_from_slice(&parity[parity_at..parity_at + 3]);
    members
}

fn put_bytes(volume: &mut Volume, path: &str, bytes: &[u8]) {
    let src = host_bytes("put", bytes);
    let wrote = volume.put(&src.0, path).unwrap();
    assert_eq!(wrote, bytes.len() as u64);
}

fn expect_get(volume: &mut Volume, path: &str, bytes: &[u8]) {
    let out = scratch("get");
    let n = volume.get(path, &out.0).unwrap();
    assert_eq!(n, bytes.len() as u64);
    assert_eq!(std::fs::read(&out.0).unwrap(), bytes);
}

fn repair_patterns(volume: &mut Volume, path: &str, body: &[u8], width: usize, failures: usize) {
    let out = scratch("repair");
    for combo in choose(width, failures) {
        let before = stripe_members(volume, path, 0);
        assert_eq!(before.len(), width, "combo {combo:?}");
        for &index in &combo {
            volume
                .testing_poke(block_offset(before[index]) + POKE_AT)
                .unwrap();
        }
        volume.get(path, &out.0).unwrap_or_else(|err| {
            panic!("{path} recover {combo:?}: {err}");
        });
        assert_eq!(std::fs::read(&out.0).unwrap(), body, "combo {combo:?}");
        let after = stripe_members(volume, path, 0);
        for index in 0..width {
            if combo.contains(&index) {
                assert_ne!(
                    after[index], before[index],
                    "damaged member {index} of {combo:?} was not rewritten"
                );
            } else {
                assert_eq!(
                    after[index], before[index],
                    "healthy member {index} of {combo:?} moved"
                );
            }
        }
    }
}

fn read_byte(volume: &mut Volume, offset: u64) -> u8 {
    let mut byte = [0u8; 1];
    read_exact_at(&mut volume.file, offset, &mut byte).unwrap();
    byte[0]
}

/// Flips one byte and leaves the directory/inode cache alone.
fn xor_byte(volume: &mut Volume, offset: u64) -> u8 {
    let mut byte = [0u8; 1];
    read_exact_at(&mut volume.file, offset, &mut byte).unwrap();
    let old = byte[0];
    byte[0] ^= 0xff;
    write_exact_at(&mut volume.file, offset, &byte).unwrap();
    volume.file.sync_all().unwrap();
    old
}

fn write_block(volume: &mut Volume, physical: u64, bytes: &[u8]) {
    assert_eq!(bytes.len(), BLOCK_SIZE as usize);
    write_exact_at(&mut volume.file, block_offset(physical), bytes).unwrap();
    volume.file.sync_all().unwrap();
    volume.block_cache.clear();
}

fn reseal_flip(
    volume: &mut Volume,
    physical: u64,
    key: &[u8; 32],
    purpose: u8,
    inode_id: u64,
    logical: u64,
    extra: u32,
    at: usize,
) {
    let plain = volume
        .read_sealed(physical, key, purpose, inode_id, logical, extra)
        .unwrap();
    let mut bytes = plain.to_vec();
    bytes[at] ^= 0xa5;
    volume
        .write_sealed(physical, &bytes, key, purpose, inode_id, logical, extra)
        .unwrap();
    volume.block_cache.clear();
}

fn snapshot_header(volume: &mut Volume) -> Vec<u8> {
    let mut buf = vec![0u8; HEADER_BYTES as usize];
    read_exact_at(&mut volume.file, 0, &mut buf).unwrap();
    buf
}

fn restore_copy(volume: &mut Volume, index: usize, snap: &[u8]) {
    let start = index * SUPER_SIZE;
    write_exact_at(
        &mut volume.file,
        start as u64,
        &snap[start..start + SUPER_SIZE],
    )
    .unwrap();
    volume.file.sync_all().unwrap();
}

fn inode_of(volume: &mut Volume, path: &str) -> super::super::Inode {
    let parsed = parse_path(path).unwrap();
    volume.walk(&parsed.components).unwrap()
}

fn no_partials(dest: &Path) {
    let dir = dest.parent().unwrap();
    let stem = dest.file_name().unwrap().to_string_lossy().to_string();
    for entry in std::fs::read_dir(dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        assert!(
            !(name.starts_with(&stem) && name.contains("hdnfs-partial")),
            "partial left behind: {name}"
        );
    }
}

#[test]
fn prefix_rejects_unsafe_init_and_keeps_the_rest_of_the_disk() {
    let mut drive = claim();
    let path = Path::new(DEVICE);
    let err = init_volume(InitOptions {
        path,
        password: PASSWORD,
        size: Some(VOLUME_BYTES),
        force: false,
        kdf: kdf(),
        progress: None,
    })
    .unwrap_err();
    assert_eq!(err.code(), "denied");

    arm_markers();
    let addressable = expected_addressable(VOLUME_BYTES);
    let slack_at = addressable;
    assert!(slack_at < VOLUME_BYTES);
    write_raw(slack_at, &[0xa5u8; 32]);
    write_raw(VOLUME_BYTES, MARKER);
    drive.fence = VOLUME_BYTES;

    let got = init_volume(InitOptions {
        path,
        password: PASSWORD,
        size: Some(VOLUME_BYTES),
        force: true,
        kdf: kdf(),
        progress: None,
    })
    .unwrap();
    assert_eq!(got, addressable);
    assert_markers();
    assert_eq!(read_raw(VOLUME_BYTES, MARKER.len()), MARKER);
    assert_ne!(read_raw(slack_at, 32), vec![0xa5u8; 32]);

    let mut volume = open_exclusive();
    put_bytes(&mut volume, "/prefix", b"prefix-ok");
    expect_get(&mut volume, "/prefix", b"prefix-ok");
    drop(volume);

    let err = init_volume(InitOptions {
        path,
        password: PASSWORD,
        size: Some(VOLUME_BYTES),
        force: false,
        kdf: kdf(),
        progress: None,
    })
    .unwrap_err();
    assert_eq!(err.code(), "denied");
    assert!(has_volume_magic(path).unwrap());
    let mut volume = open_exclusive();
    expect_get(&mut volume, "/prefix", b"prefix-ok");
    drop(volume);

    let device = block_device_bytes(path).unwrap();
    let err = init_volume(InitOptions {
        path,
        password: PASSWORD,
        size: Some(device + 1),
        force: true,
        kdf: kdf(),
        progress: None,
    })
    .unwrap_err();
    assert_eq!(err.code(), "message");
    assert!(has_volume_magic(path).unwrap());
    let mut volume = open_exclusive();
    expect_get(&mut volume, "/prefix", b"prefix-ok");
    drop(volume);

    for size in [minimum_volume_bytes() - 1, 1024] {
        let err = init_volume(InitOptions {
            path,
            password: PASSWORD,
            size: Some(size),
            force: true,
            kdf: kdf(),
            progress: None,
        })
        .unwrap_err();
        assert_eq!(err.code(), "message", "undersize {size}");
        assert!(
            has_volume_magic(path).unwrap(),
            "undersize {size} cleared magic"
        );
        let mut volume = open_exclusive();
        expect_get(&mut volume, "/prefix", b"prefix-ok");
        drop(volume);
    }
}

#[test]
fn minimum_volume_opens_and_cannot_hold_a_file() {
    let mut drive = claim();
    let min = minimum_volume_bytes();
    let mut volume = setup(&mut drive, min);
    assert!(volume.list("/").unwrap().is_empty());
    let generation = volume.generation;
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(report.repaired_blocks, 0);
    assert_eq!(report.unrepairable, 0);
    assert!(report.checked_blocks > 0);
    assert_eq!(volume.generation, generation);
    match volume.stat(None).unwrap() {
        Stat::Volume { size, .. } => assert_eq!(size, min),
        Stat::Node { .. } => panic!("volume stat"),
    }
    let src = host_bytes("nope", b"does-not-fit");
    assert_eq!(volume.put(&src.0, "/nope").unwrap_err().code(), "full");
    assert!(volume.list("/").unwrap().is_empty());
}

#[test]
fn clean_health_does_not_rewrite() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body = pattern(64, 4);
    put_bytes(&mut volume, "/note", &body);
    let generation = volume.generation;
    expect_get(&mut volume, "/note", &body);
    assert_eq!(volume.generation, generation);

    let mut stages = Vec::new();
    let mut last_done = 0u64;
    let mut total_seen = None;
    let report = volume
        .health(&mut |stage, done, total| {
            if let Some(seen) = total_seen {
                assert_eq!(seen, total);
            }
            total_seen = Some(total);
            assert!(done <= total);
            assert!(done >= last_done);
            last_done = done;
            stages.push(stage.to_string());
            Ok(())
        })
        .unwrap();
    assert_eq!(report.repaired_blocks, 0);
    assert_eq!(report.unrepairable, 0);
    assert!(report.checked_blocks > 0);
    assert_eq!(volume.generation, generation);
    assert!(stages.iter().any(|stage| stage == "bitmap"));
    assert!(stages.iter().any(|stage| stage == "/"));
    assert!(stages.iter().any(|stage| stage == "/note"));

    let again = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(again.repaired_blocks, 0);
    assert_eq!(again.unrepairable, 0);
    assert_eq!(volume.generation, generation);
    expect_get(&mut volume, "/note", &body);
    assert_eq!(volume.generation, generation);
}

#[test]
fn short_stripe_repairs_every_pattern_of_one_to_three_failures() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body = pattern(48, 9);
    put_bytes(&mut volume, "/a", &body);
    let (data, parity) = volume.testing_stripe("/a").unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(parity.len(), 3);
    for failures in 1..=3 {
        repair_patterns(&mut volume, "/a", &body, 4, failures);
    }
    expect_get(&mut volume, "/a", &body);
}

#[test]
fn two_block_stripe_repairs_up_to_three_failures() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body = pattern(PAYLOAD + 10, 11);
    put_bytes(&mut volume, "/wide", &body);
    assert_eq!(stripe_members(&mut volume, "/wide", 0).len(), 5);
    for failures in 1..=3 {
        repair_patterns(&mut volume, "/wide", &body, 5, failures);
    }
    let members = stripe_members(&mut volume, "/wide", 0);
    for &index in &[0usize, 1, 2, 3] {
        volume
            .testing_poke(block_offset(members[index]) + POKE_AT)
            .unwrap();
    }
    let dest = scratch("old");
    std::fs::write(&dest.0, b"OLD").unwrap();
    let err = volume.get("/wide", &dest.0).unwrap_err();
    assert_eq!(err.code(), "corrupt");
    assert!(err.to_string().contains("unrepairable"));
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
    no_partials(&dest.0);
}

#[test]
fn full_stripe_repairs_every_pattern_up_to_three_failures() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body = pattern(PAYLOAD * 8, 13);
    put_bytes(&mut volume, "/full", &body);
    assert_eq!(stripe_members(&mut volume, "/full", 0).len(), 11);
    for failures in 1..=3 {
        repair_patterns(&mut volume, "/full", &body, 11, failures);
    }
    let members = stripe_members(&mut volume, "/full", 0);
    for index in 0..8 {
        volume
            .testing_poke(block_offset(members[index]) + POKE_AT)
            .unwrap();
    }
    let dest = scratch("old-full");
    std::fs::write(&dest.0, b"OLD").unwrap();
    let err = volume.get("/full", &dest.0).unwrap_err();
    assert_eq!(err.code(), "corrupt");
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert!(report.unrepairable >= 1);
    let mut volume = open_exclusive_after(volume);
    assert_eq!(volume.get("/full", &dest.0).unwrap_err().code(), "corrupt");
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
}

fn open_exclusive_after(volume: Volume) -> Volume {
    drop(volume);
    open_exclusive()
}

#[test]
fn four_failures_keep_the_destination_and_the_sibling() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let bad = pattern(32, 21);
    let good = pattern(32, 22);
    put_bytes(&mut volume, "/bad", &bad);
    put_bytes(&mut volume, "/good", &good);
    let members = stripe_members(&mut volume, "/bad", 0);
    assert_eq!(members.len(), 4);
    for block in &members {
        volume.testing_poke(block_offset(*block) + POKE_AT).unwrap();
    }
    let dest = scratch("keep-old");
    std::fs::write(&dest.0, b"OLD").unwrap();
    let err = volume.get("/bad", &dest.0).unwrap_err();
    assert_eq!(err.code(), "corrupt");
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
    no_partials(&dest.0);
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert!(report.unrepairable >= 1);
    expect_get(&mut volume, "/good", &good);
    let mut volume = open_exclusive_after(volume);
    assert_eq!(volume.list("/").unwrap().len(), 2);
    drop(volume);
    let mut volume = open_exclusive();
    expect_get(&mut volume, "/good", &good);
    assert_eq!(volume.get("/bad", &dest.0).unwrap_err().code(), "corrupt");
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
}

#[test]
fn two_stripes_fail_and_repair_separately() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, WIDE_BYTES);
    let body = pattern(PAYLOAD * 8 + 64, 15);
    put_bytes(&mut volume, "/wide", &body);
    let first = stripe_members(&mut volume, "/wide", 0);
    let second = stripe_members(&mut volume, "/wide", 1);
    assert_eq!(first.len(), 11);
    assert_eq!(second.len(), 4);
    for index in 0..4 {
        volume
            .testing_poke(block_offset(first[index]) + POKE_AT)
            .unwrap();
    }
    let dest = scratch("wide-old");
    std::fs::write(&dest.0, b"OLD").unwrap();
    assert_eq!(volume.get("/wide", &dest.0).unwrap_err().code(), "corrupt");
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
    assert_eq!(stripe_members(&mut volume, "/wide", 1), second);
    put_bytes(&mut volume, "/wide", &body);
    expect_get(&mut volume, "/wide", &body);

    let first = stripe_members(&mut volume, "/wide", 0);
    let second = stripe_members(&mut volume, "/wide", 1);
    volume
        .testing_poke(block_offset(first[0]) + POKE_AT)
        .unwrap();
    volume
        .testing_poke(block_offset(second[2]) + POKE_AT)
        .unwrap();
    expect_get(&mut volume, "/wide", &body);
    let after_first = stripe_members(&mut volume, "/wide", 0);
    let after_second = stripe_members(&mut volume, "/wide", 1);
    assert_ne!(after_first[0], first[0]);
    assert_eq!(after_first[1..], first[1..]);
    assert_eq!(after_second[0], second[0]);
    assert_eq!(after_second[1], second[1]);
    assert_ne!(after_second[2], second[2]);
    assert_eq!(after_second[3], second[3]);
}

#[test]
fn health_counts_repairs_and_cancel_leaves_the_rest() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body_a = pattern(40, 31);
    let body_b = pattern(40, 32);
    put_bytes(&mut volume, "/a", &body_a);
    let members = stripe_members(&mut volume, "/a", 0);
    volume
        .testing_poke(block_offset(members[0]) + POKE_AT)
        .unwrap();
    volume
        .testing_poke(block_offset(members[3]) + POKE_AT)
        .unwrap();
    let generation = volume.generation;
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(report.repaired_blocks, 2);
    assert_eq!(report.unrepairable, 0);
    assert!(volume.generation > generation);
    expect_get(&mut volume, "/a", &body_a);
    let settled = volume.generation;
    let again = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(again.repaired_blocks, 0);
    assert_eq!(volume.generation, settled);

    put_bytes(&mut volume, "/b", &body_b);
    let a_block = stripe_members(&mut volume, "/a", 0)[0];
    let b_block = stripe_members(&mut volume, "/b", 0)[0];
    volume
        .testing_poke(block_offset(a_block) + POKE_AT)
        .unwrap();
    let b_at = block_offset(b_block) + POKE_AT;
    let original = xor_byte(&mut volume, b_at);
    let flipped = read_byte(&mut volume, b_at);
    assert_ne!(flipped, original);
    let err = volume
        .health(&mut |stage, _, _| {
            if stage == "/b" {
                Err(Error::Message("health canceled".into()))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(err.to_string(), "health canceled");
    assert_ne!(stripe_members(&mut volume, "/a", 0)[0], a_block);
    assert_eq!(read_byte(&mut volume, b_at), flipped);
    expect_get(&mut volume, "/a", &body_a);
    assert_eq!(read_byte(&mut volume, b_at), flipped);
}

#[test]
fn health_repairs_a_later_file_after_an_unrepairable_one() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let bad = pattern(24, 41);
    let good = pattern(24, 42);
    put_bytes(&mut volume, "/bad", &bad);
    put_bytes(&mut volume, "/good", &good);
    for block in stripe_members(&mut volume, "/bad", 0) {
        volume.testing_poke(block_offset(block) + POKE_AT).unwrap();
    }
    let good_block = stripe_members(&mut volume, "/good", 0)[0];
    volume
        .testing_poke(block_offset(good_block) + POKE_AT)
        .unwrap();
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert!(report.unrepairable >= 1);
    assert_eq!(report.repaired_blocks, 1);
    assert_ne!(stripe_members(&mut volume, "/good", 0)[0], good_block);
    expect_get(&mut volume, "/good", &good);
    let dest = scratch("bad-stays");
    std::fs::write(&dest.0, b"OLD").unwrap();
    assert_eq!(volume.get("/bad", &dest.0).unwrap_err().code(), "corrupt");
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
}

#[test]
fn metadata_rot_is_reconstructed_until_a_repair_persists_it() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, ROOMY_BYTES);
    let body = pattern(36, 51);
    put_bytes(&mut volume, "/docs/note", &body);
    put_bytes(&mut volume, "/p/q/file", b"deep-file");
    volume.mkdir("/empty").unwrap();

    let (dir_blocks, _) = volume.testing_stripe("/docs").unwrap();
    assert_eq!(dir_blocks.len(), 1);
    let dir_at = block_offset(dir_blocks[0]) + 24;
    let original = read_byte(&mut volume, dir_at);
    let generation = volume.generation;
    volume.testing_poke(dir_at).unwrap();
    assert_eq!(read_byte(&mut volume, dir_at), original ^ 0xff);
    assert_eq!(names(&mut volume, "/docs"), vec!["note".to_string()]);
    assert_eq!(volume.generation, generation);
    assert_eq!(read_byte(&mut volume, dir_at), original ^ 0xff);
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert!(report.repaired_blocks >= 1);
    assert_ne!(volume.testing_stripe("/docs").unwrap().0[0], dir_blocks[0]);
    expect_get(&mut volume, "/docs/note", &body);

    let content = volume.testing_stripe("/docs/note").unwrap().0[0];
    let stored = inode_of(&mut volume, "/docs/note").stored_at;
    let chain_at = block_offset(stored) + POKE_AT;
    let original = read_byte(&mut volume, chain_at);
    let generation = volume.generation;
    volume.testing_poke(chain_at).unwrap();
    match volume.stat(Some("/docs/note")).unwrap() {
        Stat::Node { kind, size, .. } => {
            assert_eq!(kind, Kind::File);
            assert_eq!(size, body.len() as u64);
        }
        Stat::Volume { .. } => panic!("node"),
    }
    assert_eq!(volume.generation, generation);
    assert_eq!(read_byte(&mut volume, chain_at), original ^ 0xff);
    volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_ne!(inode_of(&mut volume, "/docs/note").stored_at, stored);
    assert_eq!(volume.testing_stripe("/docs/note").unwrap().0[0], content);
    expect_get(&mut volume, "/docs/note", &body);

    let root_block = volume.root_inode_block;
    let root_at = block_offset(root_block) + POKE_AT;
    let original = read_byte(&mut volume, root_at);
    let generation = volume.generation;
    volume.testing_poke(root_at).unwrap();
    assert!(!names(&mut volume, "/").is_empty());
    assert_eq!(volume.generation, generation);
    assert_eq!(read_byte(&mut volume, root_at), original ^ 0xff);
    volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_ne!(volume.root_inode_block, root_block);
    expect_get(&mut volume, "/docs/note", &body);

    let parity = volume.root_parity[1];
    let generation = volume.generation;
    volume.testing_poke(block_offset(parity) + POKE_AT).unwrap();
    assert!(!names(&mut volume, "/").is_empty());
    assert_eq!(volume.generation, generation);
    volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert!(!volume.root_parity.contains(&parity));
    expect_get(&mut volume, "/p/q/file", b"deep-file");

    let empty = inode_of(&mut volume, "/empty");
    assert!(empty.content_blocks.is_empty());
    assert!(empty.content_parity.is_empty());
    assert_eq!(empty.chain_parity.len(), 3);
    let stored = empty.stored_at;
    let generation = volume.generation;
    volume.testing_poke(block_offset(stored) + POKE_AT).unwrap();
    match volume.stat(Some("/empty")).unwrap() {
        Stat::Node { kind, size, .. } => {
            assert_eq!(kind, Kind::Dir);
            assert_eq!(size, 0);
        }
        Stat::Volume { .. } => panic!("node"),
    }
    assert_eq!(volume.generation, generation);
    volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_ne!(inode_of(&mut volume, "/empty").stored_at, stored);
    assert!(names(&mut volume, "/empty").is_empty());

    let file_block = volume.testing_stripe("/p/q/file").unwrap().0[0];
    let file_at = block_offset(file_block) + 24;
    let original = read_byte(&mut volume, file_at);
    let generation = volume.generation;
    volume.testing_poke(file_at).unwrap();
    assert_eq!(names(&mut volume, "/p/q"), vec!["file".to_string()]);
    match volume.stat(Some("/p/q/file")).unwrap() {
        Stat::Node { size, .. } => assert_eq!(size, b"deep-file".len() as u64),
        Stat::Volume { .. } => panic!("node"),
    }
    assert_eq!(volume.generation, generation);
    assert_eq!(read_byte(&mut volume, file_at), original ^ 0xff);
    expect_get(&mut volume, "/p/q/file", b"deep-file");
    assert!(volume.generation > generation);
    assert_ne!(volume.testing_stripe("/p/q/file").unwrap().0[0], file_block);
}

fn names(volume: &mut Volume, path: &str) -> Vec<String> {
    volume
        .list(path)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

#[test]
fn bitmap_rot_is_rebuilt_and_four_failures_refuse_to_open() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    put_bytes(&mut volume, "/note", b"bitmap-note");
    assert_eq!(volume.bitmap_blocks_per_slot, 1);
    let base = volume.slot_base(volume.bitmap_slot);
    volume
        .testing_poke(block_offset(base + 1) + POKE_AT)
        .unwrap();
    let generation = volume.generation;
    let mut volume = open_exclusive_after(volume);
    assert!(!volume.bitmap_needs_heal);
    assert_eq!(volume.generation, generation);
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(report.repaired_blocks, 1);
    assert_eq!(report.unrepairable, 0);
    let settled = volume.generation;
    assert!(settled > generation);
    let again = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(again.repaired_blocks, 0);
    assert_eq!(volume.generation, settled);

    let base = volume.slot_base(volume.bitmap_slot);
    volume.testing_poke(block_offset(base) + POKE_AT).unwrap();
    let mut volume = open_exclusive_after(volume);
    assert!(volume.bitmap_needs_heal);
    let generation = volume.generation;
    expect_get(&mut volume, "/note", b"bitmap-note");
    assert!(volume.generation > generation);
    assert!(!volume.bitmap_needs_heal);
    let mut volume = open_exclusive_after(volume);
    assert!(!volume.bitmap_needs_heal);
    let generation = volume.generation;
    expect_get(&mut volume, "/note", b"bitmap-note");
    assert_eq!(volume.generation, generation);

    let base = volume.slot_base(volume.bitmap_slot);
    for index in 0..4 {
        volume.testing_poke(block_offset(base + index) + 7).unwrap();
    }
    drop(volume);
    match Volume::open(Path::new(DEVICE), PASSWORD, LockMode::Exclusive) {
        Err(err) => assert_eq!(err.code(), "corrupt"),
        Ok(_) => panic!("unrepairable bitmap opened"),
    }
}

#[test]
fn superblock_copies_prefer_the_highest_generation() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    // The whole prefix, not just the header. A commit scrubs blocks the old
    // root pointed at, so putting the old superblock back is not an old image.
    let image = read_raw(0, usize::try_from(VOLUME_BYTES).unwrap());
    let old = image[..HEADER_BYTES as usize].to_vec();
    put_bytes(&mut volume, "/keep", b"kept");
    assert_ne!(snapshot_header(&mut volume), old);
    restore_copy(&mut volume, 0, &old);
    restore_copy(&mut volume, 1, &old);
    let mut volume = open_exclusive_after(volume);
    expect_get(&mut volume, "/keep", b"kept");

    drop(volume);
    write_raw(0, &image);
    let mut volume = open_exclusive();
    assert!(volume.list("/").unwrap().is_empty());
    assert_eq!(
        volume
            .get("/keep", &scratch("missing-keep").0)
            .unwrap_err()
            .code(),
        "not_found"
    );
    put_bytes(&mut volume, "/keep", b"kept");
    let fresh = snapshot_header(&mut volume);

    volume.testing_poke(300).unwrap();
    let mut volume = open_exclusive_after(volume);
    volume.testing_poke(4096 + 300).unwrap();
    let mut volume = open_exclusive_after(volume);
    volume.testing_poke(8192 + 300).unwrap();
    drop(volume);
    match Volume::open(Path::new(DEVICE), PASSWORD, LockMode::Shared) {
        Err(err) => assert_eq!(err.code(), "corrupt"),
        Ok(_) => panic!("three damaged superblocks opened"),
    }

    write_raw(0, &fresh);
    let mut volume = open_exclusive();
    expect_get(&mut volume, "/keep", b"kept");
    zero_magic(&mut volume, 0);
    zero_magic(&mut volume, 1);
    let mut volume = open_exclusive_after(volume);
    expect_get(&mut volume, "/keep", b"kept");
    zero_magic(&mut volume, 2);
    drop(volume);
    assert!(!has_volume_magic(Path::new(DEVICE)).unwrap());
    match Volume::open(Path::new(DEVICE), PASSWORD, LockMode::Shared) {
        Err(err) => assert_eq!(err.code(), "not_a_volume"),
        Ok(_) => panic!("a header with no magic opened"),
    }
}

fn zero_magic(volume: &mut Volume, index: usize) {
    write_exact_at(&mut volume.file, (index * SUPER_SIZE) as u64, &[0u8; 8]).unwrap();
    volume.file.sync_all().unwrap();
}

#[test]
fn misplaced_ciphertext_fails_authentication_and_recovers() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body = pattern(PAYLOAD + 10, 7);
    put_bytes(&mut volume, "/swap", &body);
    let (data, parity) = volume.testing_stripe("/swap").unwrap();
    let left = volume.testing_read_block(data[0]).unwrap();
    let right = volume.testing_read_block(data[1]).unwrap();
    write_block(&mut volume, data[0], &right);
    write_block(&mut volume, data[1], &left);
    expect_get(&mut volume, "/swap", &body);
    let (after_data, after_parity) = volume.testing_stripe("/swap").unwrap();
    assert_ne!(after_data[0], data[0]);
    assert_ne!(after_data[1], data[1]);
    assert_eq!(after_parity, parity);

    let (data, parity) = volume.testing_stripe("/swap").unwrap();
    let copied = volume.testing_read_block(data[0]).unwrap();
    write_block(&mut volume, parity[0], &copied);
    expect_get(&mut volume, "/swap", &body);
    let (data_now, parity_now) = volume.testing_stripe("/swap").unwrap();
    assert_eq!(data_now, data);
    assert_ne!(parity_now[0], parity[0]);
    assert_eq!(parity_now[1], parity[1]);
    assert_eq!(parity_now[2], parity[2]);

    let (data, parity) = volume.testing_stripe("/swap").unwrap();
    let first = volume.testing_read_block(parity[0]).unwrap();
    let second = volume.testing_read_block(parity[1]).unwrap();
    write_block(&mut volume, parity[0], &second);
    write_block(&mut volume, parity[1], &first);
    expect_get(&mut volume, "/swap", &body);
    let (data_now, parity_now) = volume.testing_stripe("/swap").unwrap();
    assert_eq!(data_now, data);
    assert_ne!(parity_now[0], parity[0]);
    assert_ne!(parity_now[1], parity[1]);
    assert_eq!(parity_now[2], parity[2]);
}

#[test]
fn resealed_plaintext_is_unrepairable() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body = pattern(28, 61);
    put_bytes(&mut volume, "/docs/plain", &body);
    put_bytes(&mut volume, "/sealed", &body);
    put_bytes(&mut volume, "/inodefile", b"inode-body");

    let inode = inode_of(&mut volume, "/sealed");
    let (data, parity) = volume.testing_stripe("/sealed").unwrap();
    let untouched = volume.testing_read_block(parity[0]).unwrap();
    reseal_flip(
        &mut volume,
        data[0],
        &*inode.file_key,
        PURPOSE_FILE,
        inode.id,
        0,
        0,
        0,
    );
    assert_eq!(volume.testing_read_block(parity[0]).unwrap(), untouched);
    let lied = volume.testing_read_block(data[0]).unwrap();
    let dest = scratch("sealed-old");
    std::fs::write(&dest.0, b"OLD").unwrap();
    let err = volume.get("/sealed", &dest.0).unwrap_err();
    assert_eq!(err.code(), "corrupt");
    assert!(err.to_string().contains("parity mismatch"));
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert!(report.unrepairable >= 1);
    assert_eq!(volume.testing_read_block(parity[0]).unwrap(), untouched);
    assert_eq!(volume.testing_read_block(data[0]).unwrap(), lied);

    let plain = inode_of(&mut volume, "/docs/plain");
    let parity_block = volume.testing_stripe("/docs/plain").unwrap().1[1];
    let data_raw = volume.testing_read_block(plain.content_blocks[0]).unwrap();
    reseal_flip(
        &mut volume,
        parity_block,
        &*plain.file_key,
        PURPOSE_PARITY,
        plain.id,
        0,
        1,
        0,
    );
    let parity_raw = volume.testing_read_block(parity_block).unwrap();
    let err = volume.get("/docs/plain", &dest.0).unwrap_err();
    assert_eq!(err.code(), "corrupt");
    assert!(err.to_string().contains("parity mismatch"));
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
    volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(
        volume.testing_read_block(plain.content_blocks[0]).unwrap(),
        data_raw
    );
    assert_eq!(volume.testing_read_block(parity_block).unwrap(), parity_raw);

    let inode = inode_of(&mut volume, "/inodefile");
    let dek = volume.dek_copy();
    reseal_flip(
        &mut volume,
        inode.stored_at,
        &*dek,
        PURPOSE_INODE,
        inode.id,
        0,
        0,
        20,
    );
    assert!(names(&mut volume, "/").contains(&"inodefile".to_string()));
    let err = volume.stat(Some("/inodefile")).unwrap_err();
    assert_eq!(err.code(), "corrupt");
    assert!(err.to_string().contains("parity mismatch"));

    let dir = inode_of(&mut volume, "/docs");
    reseal_flip(
        &mut volume,
        dir.content_blocks[0],
        &*dir.file_key,
        PURPOSE_DIR,
        dir.id,
        0,
        0,
        0,
    );
    let err = volume.list("/docs").unwrap_err();
    assert_eq!(err.code(), "corrupt");
    assert!(err.to_string().contains("parity mismatch"));
    assert!(names(&mut volume, "/").contains(&"docs".to_string()));
}

#[test]
fn shared_lock_does_not_repair() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body = pattern(18, 71);
    put_bytes(&mut volume, "/note", &body);
    let block = volume.testing_stripe("/note").unwrap().0[0];
    volume.testing_poke(block_offset(block) + POKE_AT).unwrap();
    let generation = volume.generation;
    drop(volume);
    let mut shared = Volume::open(Path::new(DEVICE), PASSWORD, LockMode::Shared).unwrap();
    let dest = scratch("shared-old");
    std::fs::write(&dest.0, b"OLD").unwrap();
    let err = shared.get("/note", &dest.0).unwrap_err();
    assert_eq!(err.code(), "denied");
    assert!(err.to_string().contains("exclusive"));
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
    no_partials(&dest.0);
    assert_eq!(shared.generation, generation);
    assert_eq!(
        shared.health(&mut |_, _, _| Ok(())).unwrap_err().code(),
        "denied"
    );
    drop(shared);
    let mut volume = open_exclusive();
    assert_eq!(volume.generation, generation);
    expect_get(&mut volume, "/note", &body);
    assert!(volume.generation > generation);
    assert_ne!(volume.testing_stripe("/note").unwrap().0[0], block);
}

#[test]
fn directory_cache_cannot_hide_bitrot() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body = pattern(20, 81);
    put_bytes(&mut volume, "/docs/note", &body);
    assert_eq!(names(&mut volume, "/docs"), vec!["note".to_string()]);
    let dir_block = volume.testing_stripe("/docs").unwrap().0[0];
    let file_block = volume.testing_stripe("/docs/note").unwrap().0[0];
    assert!(volume.block_cache.map.contains_key(&dir_block));
    assert!(!volume.block_cache.map.contains_key(&file_block));
    let at = block_offset(dir_block) + 24;
    let original = xor_byte(&mut volume, at);
    assert!(volume.block_cache.map.contains_key(&dir_block));
    assert_ne!(read_byte(&mut volume, at), original);
    assert_eq!(names(&mut volume, "/docs"), vec!["note".to_string()]);
    assert_eq!(read_byte(&mut volume, at), original ^ 0xff);
    let generation = volume.generation;
    drop(volume);

    let mut volume = open_exclusive();
    assert_eq!(volume.generation, generation);
    assert_eq!(names(&mut volume, "/docs"), vec!["note".to_string()]);
    assert_eq!(read_byte(&mut volume, at), original ^ 0xff);
    volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_ne!(volume.testing_stripe("/docs").unwrap().0[0], dir_block);
    expect_get(&mut volume, "/docs/note", &body);
    assert!(!volume.block_cache.map.contains_key(&file_block));
}

#[test]
fn free_and_deleted_blocks_are_ignored_and_every_frame_byte_is_detected() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let body = b"unique-marker-0123456789-abcdef";
    put_bytes(&mut volume, "/secret", body);
    let live = volume.testing_stripe("/secret").unwrap().0[0];
    let before = volume.testing_read_block(live).unwrap();
    let free = free_physical(&volume);
    let generation = volume.generation;
    volume.testing_poke(block_offset(free) + POKE_AT).unwrap();
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(report.repaired_blocks, 0);
    assert_eq!(volume.generation, generation);

    volume.delete("/secret").unwrap();
    assert_ne!(volume.testing_read_block(live).unwrap(), before);
    volume.testing_poke(block_offset(live) + POKE_AT).unwrap();
    let generation = volume.generation;
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(report.repaired_blocks, 0);
    assert_eq!(volume.generation, generation);
    assert_eq!(
        volume
            .get("/secret", &scratch("gone").0)
            .unwrap_err()
            .code(),
        "not_found"
    );

    let frame = pattern(28, 91);
    put_bytes(&mut volume, "/frame", &frame);
    for offset in [0u64, 23, 24, 80, BLOCK_SIZE - 1] {
        let members = stripe_members(&mut volume, "/frame", 0);
        let poked = volume.testing_read_block(members[0]).unwrap();
        volume
            .testing_poke(block_offset(members[0]) + offset)
            .unwrap();
        let damaged = volume.testing_read_block(members[0]).unwrap();
        assert_ne!(damaged, poked);
        expect_get(&mut volume, "/frame", &frame);
        let after = stripe_members(&mut volume, "/frame", 0);
        assert_ne!(after[0], members[0], "offset {offset}");
        assert_eq!(&after[1..], &members[1..], "offset {offset}");
        assert_ne!(volume.testing_read_block(members[0]).unwrap(), damaged);
    }
    let members = stripe_members(&mut volume, "/frame", 0);
    volume.testing_poke(block_offset(members[1])).unwrap();
    expect_get(&mut volume, "/frame", &frame);
    let after = stripe_members(&mut volume, "/frame", 0);
    assert_eq!(after[0], members[0]);
    assert_ne!(after[1], members[1]);
    assert_eq!(&after[2..], &members[2..]);

    let block = stripe_members(&mut volume, "/frame", 0)[0];
    let at = block_offset(block) + POKE_AT;
    volume.testing_poke(at).unwrap();
    volume.testing_poke(at).unwrap();
    let generation = volume.generation;
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(report.repaired_blocks, 0);
    assert_eq!(volume.generation, generation);
    expect_get(&mut volume, "/frame", &frame);
}

fn free_physical(volume: &Volume) -> u64 {
    for index in 0..volume.data_block_count {
        if !volume.bit(index) {
            return volume.allocatable_start + index;
        }
    }
    panic!("no free block");
}

#[test]
fn ordinary_failures_leave_the_volume_usable() {
    let mut drive = claim();
    let mut volume = setup(&mut drive, VOLUME_BYTES);
    let empty = host_bytes("empty", b"");
    assert_eq!(volume.put(&empty.0, "/empty").unwrap(), 0);
    let (data, parity) = volume.testing_stripe("/empty").unwrap();
    assert!(data.is_empty());
    assert!(parity.is_empty());
    expect_get(&mut volume, "/empty", b"");

    assert_eq!(volume.delete("/").unwrap_err().code(), "denied");
    assert_eq!(
        volume.get("/", &scratch("root-out").0).unwrap_err().code(),
        "is_directory"
    );
    volume.mkdir("/dir").unwrap();
    assert_eq!(
        volume
            .get("/dir", &scratch("dir-out").0)
            .unwrap_err()
            .code(),
        "is_directory"
    );
    let src = host_bytes("file", b"not-a-directory");
    assert_eq!(
        volume.put(&src.0, "/dir").unwrap_err().code(),
        "type_immutable"
    );
    assert_eq!(
        volume
            .get("/missing", &scratch("missing").0)
            .unwrap_err()
            .code(),
        "not_found"
    );

    put_bytes(&mut volume, "/note", b"cancel-me");
    let dest = scratch("cancel-dest");
    std::fs::write(&dest.0, b"OLD").unwrap();
    let err = volume
        .get_with("/note", &dest.0, &mut |written, _| {
            if written > 0 {
                Err(Error::Message("get canceled".into()))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(err.to_string(), "get canceled");
    assert_eq!(std::fs::read(&dest.0).unwrap(), b"OLD");
    no_partials(&dest.0);
    expect_get(&mut volume, "/note", b"cancel-me");

    let generation = volume.generation;
    drop(volume);
    match Volume::open(
        Path::new(DEVICE),
        "not the volume password",
        LockMode::Shared,
    ) {
        Err(err) => assert_eq!(err.code(), "wrong_password"),
        Ok(_) => panic!("wrong password opened the volume"),
    }
    let mut volume = open_exclusive();
    assert_eq!(volume.generation, generation);
    expect_get(&mut volume, "/note", b"cancel-me");
    let report = volume.health(&mut |_, _, _| Ok(())).unwrap();
    assert_eq!(report.repaired_blocks, 0);
    assert_eq!(report.unrepairable, 0);
}
