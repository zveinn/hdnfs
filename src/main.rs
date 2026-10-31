use std::io::{self, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use hdnfs::{
    format_unix_utc, init_volume, parse_size, prompt_new_password, prompt_password, restore_volume,
    validate_password, wipe, Error, InitOptions, KdfParams, Kind, LockMode, Result, SecretString,
    Stat, Volume,
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
        .is_some_and(|arg| arg.eq_ignore_ascii_case("example"))
    {
        if args.len() != 1 {
            return Err(Error::Message("usage: hdnfs example".into()));
        }
        print_examples();
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
        "passwd" => cmd_passwd(volume, &args),
        "wipe" => cmd_wipe(volume, &volume_arg, &args),
        "put" => cmd_put(volume, &args),
        "get" => cmd_get(volume, &args),
        "health" => cmd_health(volume, &args),
        "backup" => cmd_backup(volume, &args),
        "restore" => cmd_restore(volume, &args),
        "del" => cmd_del(volume, &args),
        "mv" | "rename" => cmd_mv(volume, &args),
        "grow" => cmd_grow(volume, &args),
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

fn parse_wipe_args(args: &[String]) -> Result<()> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(Error::Message("usage: hdnfs <volume> wipe".into()))
    }
}

/// A file or block device that `wipe` can overwrite. A symlink is refused.
fn wipeable(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::NotFound(path.display().to_string()));
        }
        Err(err) => return Err(err.into()),
    };
    if meta.file_type().is_symlink() {
        return Err(Error::Message(format!("{} is a symlink", path.display())));
    }
    if meta.is_file() || meta.file_type().is_block_device() {
        return Ok(());
    }
    Err(Error::Message(
        "volume path is not a file or a block device".into(),
    ))
}

fn cmd_wipe(volume: &Path, volume_arg: &str, args: &[String]) -> Result<()> {
    parse_wipe_args(args)?;
    wipeable(volume)?;
    confirm_path(volume_arg)?;
    ensure_block_access(volume)?;
    let mut started = false;
    let wiped = wipe(volume, &mut |done, total| {
        started = true;
        render_bytes("wipe", done, total);
        Ok(())
    });
    if started {
        eprintln!();
    }
    let bytes = wiped?;
    println!("wiped {bytes} bytes of {}", volume.display());
    Ok(())
}

fn cmd_passwd(volume: &Path, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(Error::Message("usage: hdnfs <volume> passwd".into()));
    }
    ensure_block_access(volume)?;
    let current = ask_password("Current password: ")?;
    let mut opened = Volume::open(volume, current.expose(), LockMode::Exclusive)?;
    let next = ask_new_password()?;
    opened.change_password(next.expose())?;
    println!("password changed for {}", volume.display());
    Ok(())
}

fn ask_password(prompt: &str) -> Result<SecretString> {
    let password = SecretString::new(rpassword::prompt_password(prompt)?);
    validate_password(password.expose())?;
    Ok(password)
}

fn ask_new_password() -> Result<SecretString> {
    let first = SecretString::new(rpassword::prompt_password("New password: ")?);
    let second = SecretString::new(rpassword::prompt_password("Confirm new password: ")?);
    if first.expose() != second.expose() {
        return Err(Error::Password("passwords do not match".into()));
    }
    validate_password(first.expose())?;
    Ok(first)
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
    println!("scrubbed: {}", report.scrubbed_blocks);
    if report.unrepairable > 0 {
        return Err(Error::Corrupt(format!(
            "{} unrepairable",
            report.unrepairable
        )));
    }
    Ok(())
}

fn cmd_backup(volume: &Path, args: &[String]) -> Result<()> {
    if args.len() > 1 {
        return Err(Error::Message("usage: hdnfs <volume> backup [dest]".into()));
    }
    let dest = match args.first() {
        Some(dest) => dest.clone(),
        None => {
            eprint!("Backup path: ");
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            let typed = line.trim().to_string();
            if typed.is_empty() {
                return Err(Error::Message("empty input".into()));
            }
            typed
        }
    };
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Exclusive)?;
    let mut started = false;
    let bytes = opened.backup(Path::new(&dest), &mut |done, total| {
        started = true;
        render_bytes("backup", done, total);
        Ok(())
    })?;
    if started {
        eprintln!();
    }
    println!("backed up {bytes} bytes to {dest}");
    Ok(())
}

fn cmd_restore(volume: &Path, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        return Err(Error::Message(
            "usage: hdnfs <backup> restore <dest>".into(),
        ));
    }
    let dest = &args[0];
    ensure_block_access(volume)?;
    if is_block(Path::new(dest)) {
        ensure_block_access(Path::new(dest))?;
    }
    let password = prompt_password()?;
    let mut started = false;
    let bytes = restore_volume(
        volume,
        Path::new(dest),
        password.expose(),
        &mut |done, total| {
            started = true;
            render_bytes("restore", done, total);
            Ok(())
        },
    )?;
    if started {
        eprintln!();
    }
    println!("restored {bytes} bytes to {dest}");
    Ok(())
}

fn render_bytes(stage: &str, done: u64, total: u64) {
    let mib = 1024 * 1024;
    let total_mib = total.div_ceil(mib);
    let done_mib = if done >= total { total_mib } else { done / mib };
    render_count_bar(stage, done_mib, total_mib, "MiB");
}

fn parse_del_args(args: &[String]) -> Result<(bool, &str)> {
    let mut recursive = false;
    let mut path = None;
    for arg in args {
        match arg.as_str() {
            "-r" | "--recursive" => recursive = true,
            other if other.starts_with('-') => {
                return Err(Error::Message(format!("unknown argument {other}")));
            }
            other => {
                if path.is_some() {
                    return Err(Error::Message(
                        "usage: hdnfs <volume> del [-r | --recursive] <path>".into(),
                    ));
                }
                path = Some(other);
            }
        }
    }
    path.map(|path| (recursive, path))
        .ok_or_else(|| Error::Message("usage: hdnfs <volume> del [-r | --recursive] <path>".into()))
}

fn parse_mv_args(args: &[String]) -> Result<(&str, &str)> {
    if args.len() != 2 {
        return Err(Error::Message(
            "usage: hdnfs <volume> mv <src-path> <dest-path>".into(),
        ));
    }
    Ok((&args[0], &args[1]))
}

fn parse_grow_args(args: &[String]) -> Result<u64> {
    let mut size = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
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
    size.ok_or_else(|| Error::Message("usage: hdnfs <volume> grow --size SIZE".into()))
}

fn cmd_del(volume: &Path, args: &[String]) -> Result<()> {
    let (recursive, path) = parse_del_args(args)?;
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Exclusive)?;
    if recursive {
        let removed = opened.delete_recursive(path)?;
        println!("deleted {removed} entries at {path}");
    } else {
        opened.delete(path)?;
        println!("deleted {path}");
    }
    Ok(())
}

fn cmd_mv(volume: &Path, args: &[String]) -> Result<()> {
    let (src, dest) = parse_mv_args(args)?;
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Exclusive)?;
    let landed = opened.rename(src, dest)?;
    println!("moved {src} to {landed}");
    Ok(())
}

fn cmd_grow(volume: &Path, args: &[String]) -> Result<()> {
    let size = parse_grow_args(args)?;
    ensure_block_access(volume)?;
    let password = prompt_password()?;
    let mut opened = Volume::open(volume, password.expose(), LockMode::Exclusive)?;
    let mut started = false;
    let bytes = opened.grow(size, &mut |stage, done, total| {
        started = true;
        render_count_bar(stage, done, total, "blocks");
        Ok(())
    })?;
    if started {
        eprintln!();
    }
    println!("grew {} to {bytes} bytes", volume.display());
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
    fn bare_help_leads_with_example_and_ui() {
        let usage = usage_text();
        let commands: Vec<&str> = usage
            .lines()
            .filter(|line| line.starts_with("  hdnfs "))
            .collect();
        assert!(commands[0].contains("hdnfs example"), "{}", commands[0]);
        assert!(commands[1].contains("hdnfs ui"), "{}", commands[1]);
        assert!(!usage.contains("examples:"));
        assert!(!usage.contains("full-screen"));
        assert!(!usage.contains("SIZE is bytes"));

        let shown: Vec<&str> = example_text()
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with(' '))
            .collect();
        for line in &commands {
            let key = usage_command_key(line);
            assert!(
                shown.iter().any(|example| command_line_has(example, &key)),
                "example output has no line for {key}"
            );
        }
    }

    fn usage_command_key(line: &str) -> String {
        let rest = line.trim().strip_prefix("hdnfs ").unwrap();
        let mut parts = rest.split_whitespace();
        let first = parts.next().unwrap();
        if first.starts_with('<') {
            parts.next().unwrap().to_string()
        } else if first == "ssh" {
            let group = parts.next().unwrap();
            if group == "connect" {
                "ssh connect".to_string()
            } else {
                format!("ssh {group} {}", parts.next().unwrap())
            }
        } else {
            first.to_string()
        }
    }

    fn command_line_has(line: &str, key: &str) -> bool {
        let words: Vec<&str> = line.split_whitespace().collect();
        let key_words: Vec<&str> = key.split_whitespace().collect();
        words.windows(key_words.len()).any(|window| window == key_words)
    }

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

    #[test]
    fn del_mv_and_grow_parse_their_arguments() {
        assert_eq!(
            parse_del_args(&["/notes".into()]).unwrap(),
            (false, "/notes")
        );
        assert_eq!(
            parse_del_args(&["-r".into(), "/notes".into()]).unwrap(),
            (true, "/notes")
        );
        assert_eq!(
            parse_del_args(&["/notes".into(), "--recursive".into()]).unwrap(),
            (true, "/notes")
        );
        assert!(parse_del_args(&[]).is_err());
        assert!(parse_del_args(&["/a".into(), "/b".into()]).is_err());
        assert!(parse_del_args(&["--force".into(), "/a".into()]).is_err());

        assert_eq!(
            parse_mv_args(&["/docs/a".into(), "/docs/b".into()]).unwrap(),
            ("/docs/a", "/docs/b")
        );
        assert!(parse_mv_args(&["/docs/a".into()]).is_err());
        assert!(parse_mv_args(&["/a".into(), "/b".into(), "/c".into()]).is_err());

        assert_eq!(
            parse_grow_args(&["--size".into(), "128M".into()]).unwrap(),
            128 * 1024 * 1024
        );
        assert_eq!(
            parse_grow_args(&["--size=64M".into()]).unwrap(),
            64 * 1024 * 1024
        );
        assert!(parse_grow_args(&[]).is_err());
        assert!(parse_grow_args(&["--size".into()]).is_err());
        assert!(parse_grow_args(&["--force".into()]).is_err());

        assert!(parse_wipe_args(&[]).is_ok());
        assert!(parse_wipe_args(&["--force".into()]).is_err());
        assert!(parse_wipe_args(&["/extra".into()]).is_err());
    }
}

fn print_help() {
    println!("{}", usage_text());
}

fn print_examples() {
    println!("{}", example_text());
}

fn usage_text() -> &'static str {
    "\
hdnfs — encrypted filesystem container

usage:
  hdnfs example
  hdnfs ui
  hdnfs help
  hdnfs <volume> init [--size SIZE] [--force]
  hdnfs <volume> passwd
  hdnfs <volume> wipe
  hdnfs <volume> put <src> <dest-path>
  hdnfs <volume> get <src-path> <dest>
  hdnfs <volume> mv <src-path> <dest-path>
  hdnfs <volume> rename <src-path> <dest-path>
  hdnfs <volume> health
  hdnfs <volume> backup [dest]
  hdnfs <backup> restore <dest>
  hdnfs <volume> del [-r | --recursive] <path>
  hdnfs <volume> list [path]
  hdnfs <volume> stat [path]
  hdnfs <volume> mkdir <path>
  hdnfs <volume> grow --size SIZE
  hdnfs <volume> ssh key create <tag> [--comment TEXT]
  hdnfs <volume> ssh key add <tag> <file>
  hdnfs <volume> ssh key delete <tag>
  hdnfs <volume> ssh key list
  hdnfs <volume> ssh key info <tag>
  hdnfs <volume> ssh key get <tag> <directory>
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
  hdnfs <volume> ssh connect <tag> [-- <ssh options>]"
}

fn example_text() -> &'static str {
    "\
hdnfs example
  Prints one example of every command and a short description of what it does.

hdnfs ui
  Opens the full-screen browser. It lists disks and HDNFS files in the current directory, then unlocks or initializes the one you choose.

hdnfs help
  Prints the command list. --help and -h print the same list, alone, after the volume name, or after ssh.

hdnfs vault.img init --size 64M
  Creates a file or block-device volume. A file requires --size, and a block device with existing data requires --force.

hdnfs vault.img passwd
  Asks for the current password and a new one twice, then rewraps the data key. The files are not rewritten.

hdnfs vault.img wipe
  Overwrites every byte of the file or block device with random data and leaves the length unchanged. It asks for the path to be typed again and does not ask for the volume password.

hdnfs vault.img put ./notes.txt /archive/notes.txt
  Copies a host file or directory into the volume and creates missing parent directories. A directory is copied as a tree, and the source modification time is kept.

hdnfs vault.img get /archive/notes.txt ./notes.txt
  Copies a volume file or directory out to the host and sets the modification time again. Rebuilt blocks are written back to the volume first.

hdnfs vault.img mv /archive/notes.txt /archive/kept.txt
  Renames or moves a file or directory inside the volume. When the destination is a directory, the source is moved into it under its own name.

hdnfs vault.img rename /archive/kept.txt /archive/notes.txt
  Does the same thing as mv.

hdnfs vault.img health
  Checks every block, rewrites what it can rebuild, and overwrites free blocks with random data. It exits 1 when a stripe is beyond repair.

hdnfs vault.img backup ./vault.img.bak
  Writes the superblock and the allocated blocks to a file, leaving free blocks out. Omit the destination and the path is asked for.

hdnfs vault.img.bak restore ./vault.img
  Writes a backup back onto a file or device and fills the omitted free blocks with random data. An older byte-for-byte image still restores.

hdnfs vault.img del -r /archive/kept
  Removes a file or an empty directory. del -r and del --recursive remove a directory tree and overwrite the freed blocks.

hdnfs vault.img list /archive
  Lists the names in a directory. With no path, it lists the root of the volume.

hdnfs vault.img stat /archive/notes.txt
  Prints the type, size, and times of a file or directory. With no path, it prints the volume size and free space.

hdnfs vault.img mkdir /archive/notes
  Creates one directory.

hdnfs vault.img grow --size 128G
  Makes a file volume longer, or uses more of a block device, without moving the files already in it. The new size must still fit the allocation bitmap.

hdnfs vault.img ssh key create laptop
  Creates an ed25519 key inside the volume and prints its public line. The comment defaults to hdnfs:laptop, or set one with --comment.

hdnfs vault.img ssh key add laptop ./laptop
  Stores a private key file under the tag. The stored bytes are the file itself.

hdnfs vault.img ssh key delete laptop
  Deletes the key after you type the tag again.

hdnfs vault.img ssh key list
  Lists the keys stored in the volume, with algorithm and fingerprint when the key has them.

hdnfs vault.img ssh key info laptop
  Prints the tag, algorithm, fingerprint, comment, times, and public line.

hdnfs vault.img ssh key get laptop ./keys
  Copies the stored private key into the directory as laptop, and the public key as laptop.pub when the file yields one.

hdnfs vault.img ssh password add mail
  Stores a password you type under the tag. The secret is not printed.

hdnfs vault.img ssh password generate site --length 20
  Creates a random password, stores it, and copies it to the clipboard. Omit the flags and the length and symbols are asked for.

hdnfs vault.img ssh password list
  Lists password tags and their lengths. The secrets are not printed.

hdnfs vault.img ssh password delete mail
  Deletes the stored password after you type the tag again.

hdnfs vault.img ssh password copy mail
  Copies the stored password to the clipboard.

hdnfs vault.img ssh host create prod --key laptop --hostname 203.0.113.10 --user root
  Saves a host record that points at a stored key. User, port, timeout, and extra ssh options are optional.

hdnfs vault.img ssh host update prod --key laptop --hostname 203.0.113.11
  Replaces the saved host record for that tag. The key and hostname are required, as they are for create.

hdnfs vault.img ssh host delete prod
  Deletes the host record after you type the tag again.

hdnfs vault.img ssh host list
  Lists the saved hosts.

hdnfs vault.img ssh host info prod
  Prints the saved host record.

hdnfs vault.img ssh connect prod -- -L 8080:localhost:80
  Closes the volume, then runs ssh with the saved key and host. Anything after -- is passed through to ssh."
}
