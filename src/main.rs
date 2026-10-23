use std::io::{self, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use hdnfs::{
    format_unix_utc, init_volume, parse_size, prompt_new_password, prompt_password, Error,
    InitOptions, KdfParams, Kind, LockMode, Result, SecretString, Stat, Volume,
};

mod ssh;
mod ui;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == ssh::WAIT_ARG) {
        return Ok(ssh::wait_for_session(&args[1..]));
    }
    if args.is_empty() {
        print_help();
        std::process::exit(1);
    }
    if args.len() == 1 && is_help(&args[0]) {
        print_help();
        return Ok(ExitCode::SUCCESS);
    }
    if args
        .first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case("ui"))
    {
        if args.len() != 1 {
            return Err(Error::Message("usage: hdnfs ui".into()));
        }
        return ui::run().map(|_| ExitCode::SUCCESS);
    }
    let volume_arg = args.remove(0);
    if is_help(&volume_arg) {
        print_help();
        return Ok(ExitCode::SUCCESS);
    }
    if args.is_empty() {
        print_help();
        std::process::exit(1);
    }
    let command = args.remove(0).to_ascii_lowercase();
    let volume = Path::new(&volume_arg);
    let done = match command.as_str() {
        "init" => cmd_init(volume, &volume_arg, &args),
        "put" => cmd_put(volume, &args),
        "get" => cmd_get(volume, &args),
        "health" => cmd_health(volume, &args),
        "del" => cmd_del(volume, &args),
        "list" => cmd_list(volume, &args),
        "stat" => cmd_stat(volume, &args),
        "mkdir" => cmd_mkdir(volume, &args),
        "ssh" => return ssh::run(volume, &args),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(Error::Message(format!("unknown command {other}"))),
    };
    done.map(|_| ExitCode::SUCCESS)
}

fn is_help(arg: &str) -> bool {
    matches!(arg, "help" | "--help" | "-h")
}

fn cmd_init(volume: &Path, volume_arg: &str, args: &[String]) -> Result<()> {
    let mut size = None;
    let mut force = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--force" => force = true,
            "--size" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| Error::Message("--size needs a value".into()))?;
                size = Some(parse_size(value)?);
            }
            other if let Some(value) = other.strip_prefix("--size=") => {
                size = Some(parse_size(value)?);
            }
            other => return Err(Error::Message(format!("unknown argument {other}"))),
        }
        index += 1;
    }
    if needs_force(volume)? {
        if !force {
            return Err(Error::Denied(
                "refusing to initialize existing data without --force".into(),
            ));
        }
        confirm_path(volume_arg)?;
    } else if volume.is_file() || !volume.exists() {
        if size.is_none() && !is_block(volume) {
            return Err(Error::Message("file volumes require --size".into()));
        }
    }
    ensure_block_access(volume)?;
    let password = prompt_new_password()?;
    let mut started = false;
    let mut progress = |stage: &str, done: u64, total: u64| {
        started = true;
        render_init_bar(stage, done, total);
        Ok(())
    };
    let initialized = init_volume(InitOptions {
        path: volume,
        password: password.expose(),
        size,
        force,
        kdf: KdfParams::default(),
        progress: Some(&mut progress),
    });
    if started {
        eprintln!();
    }
    let addressable = initialized?;
    println!(
        "initialized {} ({addressable} bytes addressable)",
        volume.display()
    );
    Ok(())
}

fn needs_force(path: &Path) -> Result<bool> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.file_type().is_block_device() => Ok(true),
        Ok(meta) if meta.is_file() => Ok(meta.len() > 0),
        Ok(_) => Err(Error::Message(
            "volume path is not a file or a block device".into(),
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn is_block(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|meta| meta.file_type().is_block_device())
        .unwrap_or(false)
}

/// Open a block device the caller cannot read. Asks for the sudo password and
/// adds a read-write ACL for this user on that device node.
fn ensure_block_access(path: &Path) -> Result<()> {
    if !sudo_password_needed(path)? {
        return Ok(());
    }
    let shown = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let prompt = format!(
        "sudo password to allow {} to open {}: ",
        user_name(),
        shown.display()
    );
    let admin = SecretString::new(rpassword::prompt_password(prompt)?);
    apply_sudo_password(path, admin.expose())
}

/// True when `path` is a block device that still needs a sudo password.
/// A cached sudo credential is used first, with no prompt.
fn sudo_password_needed(path: &Path) -> Result<bool> {
    let Some(device) = checked_block_device(path)? else {
        return Ok(false);
    };
    if euid() == 0 {
        return Err(Error::Denied(format!(
            "cannot open block device {}",
            device.display()
        )));
    }
    let setfacl = setfacl_bin()?;
    if run_setfacl(&setfacl, &device, None).is_ok() && open_rw(&device).is_ok() {
        return Ok(false);
    }
    Ok(true)
}

fn apply_sudo_password(path: &Path, password: &str) -> Result<()> {
    let Some(device) = checked_block_device(path)? else {
        return Ok(());
    };
    let setfacl = setfacl_bin()?;
    run_setfacl(&setfacl, &device, Some(password))?;
    match open_rw(&device) {
        Ok(()) => Ok(()),
        Err(err) => Err(Error::Denied(format!(
            "still cannot open {}: {err}",
            device.display()
        ))),
    }
}

/// `Ok(None)` when `path` is not a block device. Permission failures stay as errors
/// only after the sudo attempt; a plain access denial is reported by the caller.
fn checked_block_device(path: &Path) -> Result<Option<PathBuf>> {
    if !is_block(path) {
        return Ok(None);
    }
    let device = std::fs::canonicalize(path)?;
    if !device.starts_with("/dev") || !is_block(&device) {
        return Err(Error::Denied(
            "refusing to change permissions outside /dev".into(),
        ));
    }
    match open_rw(&device) {
        Ok(()) => Ok(None),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Ok(Some(device)),
        Err(err) => Err(err.into()),
    }
}

fn open_rw(path: &Path) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map(|_| ())
}

fn euid() -> u32 {
    // geteuid reads the process credential and does not touch memory we own.
    unsafe { libc::geteuid() }
}

fn user_name() -> String {
    std::env::var("USER").unwrap_or_else(|_| euid().to_string())
}

fn acl_entry(uid: u32) -> String {
    format!("u:{uid}:rw")
}

fn setfacl_bin() -> Result<PathBuf> {
    for candidate in ["/usr/bin/setfacl", "/bin/setfacl"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(Error::Message(
        "setfacl is not installed; it is required to grant access to a block device".into(),
    ))
}

fn run_setfacl(setfacl: &Path, device: &Path, password: Option<&str>) -> Result<()> {
    let acl = acl_entry(euid());
    let device = device
        .to_str()
        .ok_or_else(|| Error::Message("device path is not utf-8".into()))?;
    let mut cmd = Command::new("sudo");
    cmd.arg(if password.is_some() { "-S" } else { "-n" });
    cmd.args(["-p", "", "--"])
        .arg(setfacl)
        .args(["-m", &acl, "--", device])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|err| Error::Message(format!("cannot run sudo: {err}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        if let Some(password) = password {
            stdin.write_all(password.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Denied(sudo_message(&output.stderr)))
    }
}

fn sudo_message(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("sudo refused to grant access to the block device");
    const MAX: usize = 200;
    let mut short = String::new();
    for ch in line.chars() {
        if short.len() + ch.len_utf8() > MAX {
            break;
        }
        short.push(ch);
    }
    short
}

fn confirm_path(expected: &str) -> Result<()> {
    eprint!("Type the volume path to confirm: ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let typed = line.trim_end_matches(['\n', '\r']);
    if typed != expected {
        return Err(Error::Denied(
            "confirmation did not match the volume path".into(),
        ));
    }
    Ok(())
}

fn cmd_put(volume: &Path, args: &[String]) -> Result<()> {
    if args.len() != 2 {
        return Err(Error::Message(
            "usage: hdnfs <volume> put <src> <dest-path>".into(),
        ));
    }
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Exclusive)?;
    let bytes = opened.put(Path::new(&args[0]), &args[1])?;
    println!("wrote {bytes} bytes to {}", args[1]);
    Ok(())
}

fn cmd_get(volume: &Path, args: &[String]) -> Result<()> {
    if args.len() != 2 {
        return Err(Error::Message(
            "usage: hdnfs <volume> get <src-path> <dest>".into(),
        ));
    }
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Exclusive)?;
    let bytes = opened.get(&args[0], Path::new(&args[1]))?;
    println!("extracted {} to {} ({bytes} bytes)", args[0], args[1]);
    Ok(())
}

fn cmd_health(volume: &Path, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(Error::Message("usage: hdnfs <volume> health".into()));
    }
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Exclusive)?;
    let mut started = false;
    let report = opened.health(&mut |stage, done, total| {
        started = true;
        render_count_bar(stage, done, total, "blocks");
        Ok(())
    })?;
    if started {
        eprintln!();
    }
    println!("checked: {}", report.checked_blocks);
    println!("repaired: {}", report.repaired_blocks);
    println!("unrepairable: {}", report.unrepairable);
    if report.unrepairable > 0 {
        return Err(Error::Corrupt(format!(
            "{} unrepairable",
            report.unrepairable
        )));
    }
    Ok(())
}

fn cmd_del(volume: &Path, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        return Err(Error::Message("usage: hdnfs <volume> del <path>".into()));
    }
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Exclusive)?;
    opened.delete(&args[0])?;
    println!("deleted {}", args[0]);
    Ok(())
}

fn cmd_list(volume: &Path, args: &[String]) -> Result<()> {
    if args.len() > 1 {
        return Err(Error::Message("usage: hdnfs <volume> list [path]".into()));
    }
    let path = args.first().map(String::as_str).unwrap_or("/");
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Shared)?;
    for entry in opened.list(path)? {
        match entry.kind {
            Kind::Dir => println!("d {}", entry.name),
            Kind::File => println!("f {} {}", entry.size, entry.name),
        }
    }
    Ok(())
}

fn cmd_stat(volume: &Path, args: &[String]) -> Result<()> {
    if args.len() > 1 {
        return Err(Error::Message("usage: hdnfs <volume> stat [path]".into()));
    }
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Shared)?;
    match opened.stat(args.first().map(String::as_str))? {
        Stat::Volume {
            size,
            block_size,
            data_blocks,
            used_blocks,
            free_blocks,
            free_payload_bytes,
        } => {
            println!("type: volume");
            println!("size: {size}");
            println!("block_size: {block_size}");
            println!("data_blocks: {data_blocks}");
            println!("used_blocks: {used_blocks}");
            println!("free_blocks: {free_blocks}");
            println!("free_payload_bytes: {free_payload_bytes}");
        }
        Stat::Node {
            path,
            kind,
            size,
            created,
            modified,
        } => {
            println!("type: {}", kind.as_str());
            println!("path: {path}");
            println!("size: {size}");
            println!("created: {}", hdnfs_time(created));
            println!("modified: {}", hdnfs_time(modified));
        }
    }
    Ok(())
}

fn cmd_mkdir(volume: &Path, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        return Err(Error::Message("usage: hdnfs <volume> mkdir <path>".into()));
    }
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Exclusive)?;
    opened.mkdir(&args[0])?;
    println!("created {}", args[0]);
    Ok(())
}

fn hdnfs_time(secs: i64) -> String {
    format_unix_utc(secs)
}

fn render_init_bar(stage: &str, done: u64, total: u64) {
    render_count_bar(stage, done, total, "MiB");
}

fn render_count_bar(stage: &str, done: u64, total: u64, unit: &str) {
    let pct = if total == 0 {
        100
    } else {
        (done.saturating_mul(100) / total).min(100)
    };
    let width = 30;
    let filled = (pct as usize * width / 100).min(width);
    let bar = format!("{}{}", "#".repeat(filled), "-".repeat(width - filled));
    eprint!("\r{stage} [{bar}] {pct:>3}%  {done}/{total} {unit}");
    let _ = io::stderr().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_entry_names_this_user() {
        assert_eq!(acl_entry(1000), "u:1000:rw");
    }

    #[test]
    fn sudo_message_keeps_the_first_line() {
        assert_eq!(
            sudo_message(b"sudo: a password is required\n"),
            "sudo: a password is required"
        );
        assert_eq!(
            sudo_message(b"   \n"),
            "sudo refused to grant access to the block device"
        );
    }
}

fn print_help() {
    println!(
        r#"hdnfs — encrypted filesystem container

usage:
  hdnfs ui
  hdnfs <volume> init [--size SIZE] [--force]
  hdnfs <volume> put <src> <dest-path>
  hdnfs <volume> get <src-path> <dest>
  hdnfs <volume> health
  hdnfs <volume> del <path>
  hdnfs <volume> list [path]
  hdnfs <volume> stat [path]
  hdnfs <volume> mkdir <path>
  hdnfs <volume> ssh key create <tag> [--comment TEXT]
  hdnfs <volume> ssh key add <tag> <file>
  hdnfs <volume> ssh key delete <tag>
  hdnfs <volume> ssh key list
  hdnfs <volume> ssh key info <tag>
  hdnfs <volume> ssh host create <tag> --key <key-tag> --hostname <host> [--user USER] [--port N] [--timeout SECONDS] [--option LINE]
  hdnfs <volume> ssh host update <tag> --key <key-tag> --hostname <host> [--user USER] [--port N] [--timeout SECONDS] [--option LINE]
  hdnfs <volume> ssh host delete <tag>
  hdnfs <volume> ssh host list
  hdnfs <volume> ssh host info <tag>
  hdnfs <volume> ssh connect <tag> [-- <ssh options>]

hdnfs ui opens a full-screen browser. It lists disks, unlocks an existing
volume, or initializes one. The commands above stay available.

SIZE is bytes, with an optional binary suffix: K, M, G, T (also KB/KiB and so on).
File volumes require --size. A block device uses the whole device unless --size
is set, and that size cannot be larger than the device. Block devices require --force.
If you cannot open a block device, hdnfs asks for your sudo password and grants
your user read-write on that device node. The volume password is a separate prompt.
init asks for the volume password twice. Every other command asks once.
put creates missing directories. A name cannot change between file and directory.
get rewrites the volume copy when it has to rebuild damaged blocks.
health checks every block, rewrites what it can rebuild, and exits 1 if any
stripe has more damage than parity can repair.

examples:
  hdnfs vault.img init --size 64M
  hdnfs /dev/sda init --force --size 1G
  hdnfs vault.img put ./notes.txt /path1/path2/path3/file
  hdnfs vault.img get /path1/path2/path3/file ./notes.txt
  hdnfs vault.img health
  hdnfs vault.img list /path1
"#
    );
}
