use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set once `disable_process_dumps` succeeds. `ssh` opens this process's
/// `/proc/<pid>/fd` paths, which the kernel hides while the process is not
/// dumpable, so a session may turn that bit back on until it exits.
static PROC_PRIVATE: AtomicBool = AtomicBool::new(false);

pub fn flock_exclusive(file: &File) -> io::Result<()> {
    flock(file, libc::LOCK_EX | libc::LOCK_NB)
}

pub fn flock_shared(file: &File) -> io::Result<()> {
    flock(file, libc::LOCK_SH | libc::LOCK_NB)
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

/// Pin `bytes` in RAM and leave that page out of core dumps.
///
/// The lock covers the whole page. If it fails, the locked-memory soft limit
/// is raised by one page, up to the hard limit, and the lock is tried once more.
pub fn mlock_bytes(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    if lock_pages(bytes).is_err() {
        raise_memlock_one_page()?;
        lock_pages(bytes)?;
    }
    if let Err(err) = advise(bytes, libc::MADV_DONTDUMP) {
        unlock_pages(bytes);
        return Err(err);
    }
    Ok(())
}

pub fn munlock_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let _ = advise(bytes, libc::MADV_DODUMP);
    unlock_pages(bytes);
}

/// Refuse core dumps, and require `CAP_SYS_PTRACE` to read this process.
pub fn disable_process_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    set_dumpable(false)?;
    PROC_PRIVATE.store(true, Ordering::SeqCst);
    Ok(())
}

/// Let `ssh` and its `LocalCommand` open `/proc/<pid>/fd`. Core dumps stay off.
/// A process that never called `disable_process_dumps` is left unchanged.
pub fn allow_proc_fd_access() -> io::Result<()> {
    if !PROC_PRIVATE.load(Ordering::SeqCst) {
        return Ok(());
    }
    set_dumpable(true)
}

/// Hide `/proc/<pid>` again after `ssh` no longer needs those paths.
pub fn restore_proc_privacy() {
    if PROC_PRIVATE.load(Ordering::SeqCst) {
        let _ = set_dumpable(false);
    }
}

fn set_dumpable(enabled: bool) -> io::Result<()> {
    let value: libc::c_ulong = if enabled { 1 } else { 0 };
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            value,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn lock_pages(bytes: &[u8]) -> io::Result<()> {
    let (addr, len) = page_span(bytes);
    let rc = unsafe { libc::mlock(addr, len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlock_pages(bytes: &[u8]) {
    let (addr, len) = page_span(bytes);
    let _ = unsafe { libc::munlock(addr, len) };
}

fn advise(bytes: &[u8], advice: libc::c_int) -> io::Result<()> {
    let (addr, len) = page_span(bytes);
    let rc = unsafe { libc::madvise(addr, len, advice) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `madvise` requires a page-aligned address. The pointer is only passed to
/// the kernel; it is not dereferenced.
fn page_span(bytes: &[u8]) -> (*mut libc::c_void, usize) {
    let page = page_size();
    let start = bytes.as_ptr() as usize;
    let end = start + bytes.len();
    let aligned = start & !(page - 1);
    let span = (end - aligned).div_ceil(page) * page;
    (aligned as *mut libc::c_void, span)
}

fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 {
        4096
    } else {
        size as usize
    }
}

fn raise_memlock_one_page() -> io::Result<()> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if lim.rlim_cur == libc::RLIM_INFINITY {
        return Ok(());
    }
    let page = page_size() as libc::rlim_t;
    let room = if lim.rlim_max == libc::RLIM_INFINITY {
        page
    } else if lim.rlim_cur >= lim.rlim_max {
        0
    } else {
        page.min(lim.rlim_max - lim.rlim_cur)
    };
    if room == 0 {
        return Ok(());
    }
    lim.rlim_cur += room;
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_exclusive_lock_does_not_wait() {
        let path = std::env::temp_dir().join(format!(
            "hdnfs-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let held = std::fs::File::create(&path).unwrap();
        flock_exclusive(&held).unwrap();
        let other = std::fs::File::open(&path).unwrap();
        let err = flock_exclusive(&other).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        drop(held);
        drop(other);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mlock_pins_the_page_and_excludes_it_from_dumps() {
        let page = page_size();
        let mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mem, libc::MAP_FAILED);
        let bytes = unsafe { std::slice::from_raw_parts(mem as *const u8, 32) };
        mlock_bytes(bytes).unwrap();
        let flags = vm_flags(mem as usize).expect("smaps entry");
        assert!(flag_set(&flags, "lo"), "{flags}");
        assert!(flag_set(&flags, "dd"), "{flags}");
        munlock_bytes(bytes);
        let flags = vm_flags(mem as usize).expect("smaps entry after unlock");
        assert!(!flag_set(&flags, "lo"), "{flags}");
        assert!(!flag_set(&flags, "dd"), "{flags}");
        unsafe { libc::munmap(mem, page) };
    }

    #[test]
    fn process_dumps_can_be_disabled() {
        disable_process_dumps().unwrap();
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert_eq!(dumpable, 0);
        let mut lim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
        assert_eq!(rc, 0);
        assert_eq!(lim.rlim_cur, 0);
        assert_eq!(lim.rlim_max, 0);

        // ssh reads the key and config through /proc/<pid>/fd. That directory
        // is root-only while the process is not dumpable, and readable again
        // for the session that calls allow_proc_fd_access.
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let path = format!("/proc/{}/fd/{}", std::process::id(), fds[0]);
        assert!(
            !child_can_open(&path),
            "a child must not open /proc/pid/fd while dumps are disabled"
        );
        allow_proc_fd_access().unwrap();
        assert!(
            child_can_open(&path),
            "ssh must be able to open /proc/pid/fd during a session"
        );
        restore_proc_privacy();
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
        assert!(
            !child_can_open(&path),
            "dropping the ssh session must hide /proc/pid/fd again"
        );
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    /// True when `cat` can open `path` and block on it. A permission error
    /// makes `cat` exit. The write end stays open, so a successful open blocks.
    fn child_can_open(path: &str) -> bool {
        let mut child = std::process::Command::new("cat")
            .arg(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status.success();
            }
            if started.elapsed() > std::time::Duration::from_millis(200) {
                let _ = child.kill();
                let _ = child.wait();
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn flag_set(flags: &str, flag: &str) -> bool {
        flags.split_whitespace().any(|item| item == flag)
    }

    fn vm_flags(addr: usize) -> Option<String> {
        let text = std::fs::read_to_string("/proc/self/smaps").ok()?;
        let mut in_region = false;
        for line in text.lines() {
            if let Some((range, _)) = line.split_once(' ') {
                if let Some((start, end)) = range.split_once('-') {
                    if let (Ok(start), Ok(end)) = (
                        usize::from_str_radix(start, 16),
                        usize::from_str_radix(end, 16),
                    ) {
                        in_region = addr >= start && addr < end;
                        continue;
                    }
                }
            }
            if in_region {
                if let Some(flags) = line.strip_prefix("VmFlags:") {
                    return Some(flags.trim().to_string());
                }
            }
        }
        None
    }
}
