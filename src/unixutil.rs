use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

pub fn flock_exclusive(file: &File) -> io::Result<()> {
    flock(file, libc::LOCK_EX)
}

pub fn flock_shared(file: &File) -> io::Result<()> {
    flock(file, libc::LOCK_SH)
}

pub fn flock_unlock(file: &File) -> io::Result<()> {
    flock(file, libc::LOCK_UN)
}

fn flock(file: &File, op: i32) -> io::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `BLKGETSIZE64` = `_IOR(0x12, 114, u64)` on 64-bit Linux. The libc crate does not export it.
const BLKGETSIZE64: libc::Ioctl = 0x8008_1272;

pub fn block_device_size(file: &File) -> io::Result<u64> {
    let mut size: u64 = 0;
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64, &mut size) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(size)
    }
}

pub fn mlock_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let _ = unsafe { libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) };
}

pub fn munlock_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let _ = unsafe { libc::munlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) };
}
