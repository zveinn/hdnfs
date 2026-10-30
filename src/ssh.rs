use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hdnfs::{
    allow_proc_fd_access, format_unix_utc, restore_proc_privacy, Error, Kind, LockMode, Result,
    Stat, Volume,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_TAG: usize = 64;
const MAX_HOSTNAME: usize = 255;
const MAX_USER: usize = 64;
const MAX_COMMENT: usize = 128;
const MAX_OPTION: usize = 1024;
const MAX_OPTIONS: usize = 64;
const MAX_PUBLIC: usize = 16 * 1024;
const MAX_PRIVATE: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInfo {
    pub algorithm: String,
    pub fingerprint: String,
    pub comment: String,
    pub line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRecord {
    pub key: String,
    pub hostname: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// `ConnectTimeout`, in seconds. Empty means OpenSSH's own default.
    pub timeout: Option<u32>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    pub tag: String,
    pub detail: KeyDetail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDetail {
    Ready(PublicInfo),
    /// Private bytes are stored. The file did not yield a public line.
    Raw,
    Incomplete,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRow {
    pub tag: String,
    pub target: String,
    pub key: String,
}

pub struct Session {
    config: String,
    private_key: Zeroizing<Vec<u8>>,
}

/// How `ssh` ended, plus the error text it wrote.
pub struct SshStatus {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub stderr: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyMeta {
    version: u32,
    /// Present when the stored file parsed as an OpenSSH private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    version: u32,
    key: String,
    hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    /// Seconds for OpenSSH `ConnectTimeout`. Absent on records written before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    options: Vec<String>,
}

pub struct HostInput {
    pub tag: String,
    pub key: String,
    pub hostname: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub timeout: Option<u32>,
    pub options: Vec<String>,
}

pub fn run(volume: &Path, args: &[String]) -> Result<ExitCode> {
    if args.is_empty() {
        return Err(Error::Message(ssh_usage().into()));
    }
    match args[0].to_ascii_lowercase().as_str() {
        "key" => run_key(volume, &args[1..]),
        "host" => run_host(volume, &args[1..]),
        "password" => run_password(volume, &args[1..]),
        "connect" => run_connect(volume, &args[1..]),
        "help" | "--help" | "-h" => {
            println!("{}", ssh_usage());
            Ok(ExitCode::SUCCESS)
        }
        other => Err(Error::Message(format!(
            "unknown ssh command {other}\n{}",
            ssh_usage()
        ))),
    }
}

fn ssh_usage() -> &'static str {
    "\
usage:
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

fn run_key(volume: &Path, args: &[String]) -> Result<ExitCode> {
    if args.is_empty() {
        return Err(Error::Message(
            "usage: hdnfs <volume> ssh key create|add|delete|list|info|get".into(),
        ));
    }
    match args[0].to_ascii_lowercase().as_str() {
        "create" => {
            let (tag, comment) = parse_key_create(&args[1..])?;
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            let info = create_key(&mut opened, &tag, comment.as_deref())?;
            println!("{}", info.line);
            Ok(ExitCode::SUCCESS)
        }
        "add" => {
            if args.len() != 3 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh key add <tag> <file>".into(),
                ));
            }
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            match add_key(&mut opened, &args[1], Path::new(&args[2]))? {
                Some(info) => println!("{}", info.line),
                None => println!("added key {}", args[1]),
            }
            Ok(ExitCode::SUCCESS)
        }
        "delete" => {
            if args.len() != 2 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh key delete <tag>".into(),
                ));
            }
            validate_tag(&args[1])?;
            confirm_tag(&args[1])?;
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            delete_key(&mut opened, &args[1])?;
            println!("deleted key {}", args[1]);
            Ok(ExitCode::SUCCESS)
        }
        "list" => {
            if args.len() != 1 {
                return Err(Error::Message("usage: hdnfs <volume> ssh key list".into()));
            }
            let mut opened = open_volume(volume, LockMode::Shared)?;
            for row in list_keys(&mut opened)? {
                println!("{}", format_key_row(&row));
            }
            Ok(ExitCode::SUCCESS)
        }
        "info" => {
            if args.len() != 2 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh key info <tag>".into(),
                ));
            }
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            print!("{}", key_info(&mut opened, &args[1])?);
            Ok(ExitCode::SUCCESS)
        }
        "get" => {
            if args.len() != 3 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh key get <tag> <directory>".into(),
                ));
            }
            let mut opened = open_volume(volume, LockMode::Shared)?;
            let exported = export_key(&mut opened, &args[1], Path::new(&args[2]))?;
            println!("wrote {}", exported.private_path.display());
            match &exported.public_path {
                Some(path) => println!("wrote {}", path.display()),
                None => println!("key {} did not yield a public line", args[1]),
            }
            Ok(ExitCode::SUCCESS)
        }
        other => Err(Error::Message(format!("unknown ssh key command {other}"))),
    }
}

fn run_host(volume: &Path, args: &[String]) -> Result<ExitCode> {
    if args.is_empty() {
        return Err(Error::Message(
            "usage: hdnfs <volume> ssh host create|update|delete|list|info".into(),
        ));
    }
    match args[0].to_ascii_lowercase().as_str() {
        "create" => {
            let input = parse_host_args(&args[1..])?;
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            create_host(&mut opened, &input)?;
            println!("created host {}", input.tag);
            Ok(ExitCode::SUCCESS)
        }
        "update" => {
            let input = parse_host_args(&args[1..])?;
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            update_host(&mut opened, &input)?;
            println!("updated host {}", input.tag);
            Ok(ExitCode::SUCCESS)
        }
        "delete" => {
            if args.len() != 2 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh host delete <tag>".into(),
                ));
            }
            validate_tag(&args[1])?;
            confirm_tag(&args[1])?;
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            delete_host(&mut opened, &args[1])?;
            println!("deleted host {}", args[1]);
            Ok(ExitCode::SUCCESS)
        }
        "list" => {
            if args.len() != 1 {
                return Err(Error::Message("usage: hdnfs <volume> ssh host list".into()));
            }
            let mut opened = open_volume(volume, LockMode::Shared)?;
            for row in list_hosts(&mut opened)? {
                println!("{}", format_host_row(&row));
            }
            Ok(ExitCode::SUCCESS)
        }
        "info" => {
            if args.len() != 2 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh host info <tag>".into(),
                ));
            }
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            print!("{}", host_info(&mut opened, &args[1])?);
            Ok(ExitCode::SUCCESS)
        }
        other => Err(Error::Message(format!("unknown ssh host command {other}"))),
    }
}

fn run_password(volume: &Path, args: &[String]) -> Result<ExitCode> {
    if args.is_empty() {
        return Err(Error::Message(
            "usage: hdnfs <volume> ssh password add|generate|list|delete|copy".into(),
        ));
    }
    match args[0].to_ascii_lowercase().as_str() {
        "add" => {
            if args.len() != 2 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh password add <tag>".into(),
                ));
            }
            validate_tag(&args[1])?;
            let secret = prompt_stored_password()?;
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            add_password(&mut opened, &args[1], &secret)?;
            println!("added password {}", args[1]);
            Ok(ExitCode::SUCCESS)
        }
        "generate" => {
            let (tag, length, symbols) = parse_password_generate(&args[1..])?;
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            generate_password_record(&mut opened, &tag, length, symbols)?;
            println!("generated password {tag}");
            Ok(ExitCode::SUCCESS)
        }
        "list" => {
            if args.len() != 1 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh password list".into(),
                ));
            }
            let mut opened = open_volume(volume, LockMode::Shared)?;
            for row in list_passwords(&mut opened)? {
                println!("{}", format_password_row(&row));
            }
            Ok(ExitCode::SUCCESS)
        }
        "delete" => {
            if args.len() != 2 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh password delete <tag>".into(),
                ));
            }
            validate_tag(&args[1])?;
            confirm_tag(&args[1])?;
            let mut opened = open_volume(volume, LockMode::Exclusive)?;
            delete_password(&mut opened, &args[1])?;
            println!("deleted password {}", args[1]);
            Ok(ExitCode::SUCCESS)
        }
        "copy" => {
            if args.len() != 2 {
                return Err(Error::Message(
                    "usage: hdnfs <volume> ssh password copy <tag>".into(),
                ));
            }
            let mut opened = open_volume(volume, LockMode::Shared)?;
            copy_password(&mut opened, &args[1])?;
            println!("copied {}", args[1]);
            Ok(ExitCode::SUCCESS)
        }
        other => Err(Error::Message(format!(
            "unknown ssh password command {other}"
        ))),
    }
}

fn prompt_stored_password() -> Result<Zeroizing<String>> {
    let mut first = Zeroizing::new(rpassword::prompt_password("Enter password: ")?);
    let mut second = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
    let matches = first.as_str() == second.as_str();
    second.zeroize();
    if !matches {
        first.zeroize();
        return Err(Error::Message("passwords do not match".into()));
    }
    if let Err(err) = validate_stored_password(&first) {
        first.zeroize();
        return Err(err);
    }
    Ok(first)
}

fn prompt_line(label: &str) -> Result<String> {
    eprint!("{label}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if line.is_empty() {
        return Err(Error::Message("empty input".into()));
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn parse_password_generate(args: &[String]) -> Result<(String, usize, bool)> {
    if args.is_empty() {
        return Err(Error::Message(
            "usage: hdnfs <volume> ssh password generate <tag> [--length N] [--symbols | --no-symbols]"
                .into(),
        ));
    }
    let tag = args[0].clone();
    validate_tag(&tag)?;
    let mut length = None;
    let mut symbols = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--symbols" => {
                if symbols.is_some() {
                    return Err(Error::Message("symbols was set twice".into()));
                }
                symbols = Some(true);
            }
            "--no-symbols" => {
                if symbols.is_some() {
                    return Err(Error::Message("symbols was set twice".into()));
                }
                symbols = Some(false);
            }
            "--length" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| Error::Message("--length needs a value".into()))?;
                if length.is_some() {
                    return Err(Error::Message("length was set twice".into()));
                }
                length = Some(parse_password_length(value)?);
            }
            other => {
                if let Some(value) = other.strip_prefix("--length=") {
                    if length.is_some() {
                        return Err(Error::Message("length was set twice".into()));
                    }
                    length = Some(parse_password_length(value)?);
                } else {
                    return Err(Error::Message(format!("unknown argument {other}")));
                }
            }
        }
        index += 1;
    }
    let length = match length {
        Some(length) => length,
        None => parse_password_length(&prompt_line("Length: ")?)?,
    };
    let symbols = match symbols {
        Some(symbols) => symbols,
        None => parse_yes_no(&prompt_line("Include symbols? [y/n]: ")?)?,
    };
    Ok((tag, length, symbols))
}

fn run_connect(volume: &Path, args: &[String]) -> Result<ExitCode> {
    let (tag, extra) = parse_connect(args)?;
    reject_extra(&extra)?;
    let mut opened = open_volume(volume, LockMode::Exclusive)?;
    let session = load_session(&mut opened, tag)?;
    drop(opened);
    let status = run_session(session, &extra)?;
    if let Some(text) = status.failure_note() {
        eprintln!("{text}");
    }
    Ok(status.exit_code())
}

fn open_volume(path: &Path, lock: LockMode) -> Result<Volume> {
    super::ensure_block_access(path)?;
    let password = hdnfs::prompt_password()?;
    Volume::open(path, password.expose(), lock)
}

fn confirm_tag(tag: &str) -> Result<()> {
    eprint!("Type the tag to confirm: ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if line.trim_end_matches(['\n', '\r']) != tag {
        return Err(Error::Denied("confirmation did not match the tag".into()));
    }
    Ok(())
}

pub fn validate_tag(tag: &str) -> Result<()> {
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return Err(Error::Message(
            "a tag is 1 to 64 bytes of letters, digits, '.', '_', or '-'".into(),
        ));
    };
    if tag.len() > MAX_TAG
        || !first.is_ascii_alphanumeric()
        || !tag
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(Error::Message(
            "a tag is 1 to 64 bytes of letters, digits, '.', '_', or '-'".into(),
        ));
    }
    Ok(())
}

pub fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty()
        || hostname.len() > MAX_HOSTNAME
        || hostname
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '@' || ch == '/')
    {
        return Err(Error::Message(
            "hostname must be a DNS name or IP without @, /, or whitespace".into(),
        ));
    }
    Ok(())
}

pub fn validate_user(user: &str) -> Result<()> {
    if user.is_empty()
        || user.len() > MAX_USER
        || user.chars().any(|ch| ch.is_whitespace() || ch == '@')
    {
        return Err(Error::Message(
            "user must be 1 to 64 bytes without @ or whitespace".into(),
        ));
    }
    Ok(())
}

fn validate_comment(comment: &str) -> Result<()> {
    if comment.is_empty()
        || comment.len() > MAX_COMMENT
        || comment.chars().any(|ch| ch.is_control())
    {
        return Err(Error::Message(
            "comment must be 1 to 128 bytes without control characters".into(),
        ));
    }
    Ok(())
}

pub fn validate_option_line(line: &str) -> Result<()> {
    if line.is_empty() || line.len() > MAX_OPTION || line.chars().any(|ch| ch.is_control()) {
        return Err(Error::Message(
            "an option is one ssh keyword line, at most 1024 bytes".into(),
        ));
    }
    let keyword = line.split_whitespace().next().unwrap_or("");
    if keyword.is_empty() || !keyword.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Err(Error::Message(format!("invalid ssh option '{line}'")));
    }
    if forbidden_keyword(keyword) {
        return Err(Error::Denied(format!("ssh option {keyword} is reserved")));
    }
    Ok(())
}

fn forbidden_keyword(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "host"
            | "match"
            | "include"
            | "identityfile"
            | "identitiesonly"
            | "identityagent"
            | "certificatefile"
            | "pkcs11provider"
            | "localcommand"
            | "permitlocalcommand"
            | "connecttimeout"
    )
}

pub fn parse_timeout(text: &str) -> Result<u32> {
    let timeout: u32 = text
        .parse()
        .map_err(|_| Error::Message(format!("invalid timeout {text}")))?;
    if !(1..=3600).contains(&timeout) {
        return Err(Error::Message(
            "timeout must be from 1 to 3600 seconds".into(),
        ));
    }
    Ok(timeout)
}

pub fn parse_port(text: &str) -> Result<u16> {
    let port: u16 = text
        .parse()
        .map_err(|_| Error::Message(format!("invalid port {text}")))?;
    if port == 0 {
        return Err(Error::Message("port must be from 1 to 65535".into()));
    }
    Ok(port)
}

fn parse_key_create(args: &[String]) -> Result<(String, Option<String>)> {
    let mut tag = None;
    let mut comment = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(name) = arg.strip_prefix("--") {
            let (name, inline) = split_flag(name);
            if name != "comment" {
                return Err(Error::Message(format!("unknown argument --{name}")));
            }
            if comment.is_some() {
                return Err(Error::Message("--comment is already set".into()));
            }
            let value = flag_value(args, &mut index, inline, "--comment")?;
            validate_comment(&value)?;
            comment = Some(value);
        } else if tag.is_some() {
            return Err(Error::Message(format!("unexpected argument {arg}")));
        } else {
            validate_tag(arg)?;
            tag = Some(arg.clone());
        }
        index += 1;
    }
    let tag = tag.ok_or_else(|| {
        Error::Message("usage: hdnfs <volume> ssh key create <tag> [--comment TEXT]".into())
    })?;
    Ok((tag, comment))
}

pub fn parse_host_args(args: &[String]) -> Result<HostInput> {
    let mut tag = None;
    let mut key = None;
    let mut hostname = None;
    let mut user = None;
    let mut port = None;
    let mut timeout = None;
    let mut options = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(name) = arg.strip_prefix("--") {
            let (name, inline) = split_flag(name);
            match name {
                "key" => {
                    let value = flag_value(args, &mut index, inline, "--key")?;
                    assign_once(&mut key, value, "--key")?;
                }
                "hostname" => {
                    let value = flag_value(args, &mut index, inline, "--hostname")?;
                    assign_once(&mut hostname, value, "--hostname")?;
                }
                "user" => {
                    let value = flag_value(args, &mut index, inline, "--user")?;
                    assign_once(&mut user, value, "--user")?;
                }
                "port" => {
                    if port.is_some() {
                        return Err(Error::Message("--port is already set".into()));
                    }
                    let value = flag_value(args, &mut index, inline, "--port")?;
                    port = Some(parse_port(&value)?);
                }
                "timeout" => {
                    if timeout.is_some() {
                        return Err(Error::Message("--timeout is already set".into()));
                    }
                    let value = flag_value(args, &mut index, inline, "--timeout")?;
                    timeout = Some(parse_timeout(&value)?);
                }
                "option" => {
                    if options.len() == MAX_OPTIONS {
                        return Err(Error::Message("a host can have at most 64 options".into()));
                    }
                    let value = flag_value(args, &mut index, inline, "--option")?;
                    validate_option_line(&value)?;
                    options.push(value);
                }
                other => return Err(Error::Message(format!("unknown argument --{other}"))),
            }
        } else if tag.is_some() {
            return Err(Error::Message(format!("unexpected argument {arg}")));
        } else {
            validate_tag(arg)?;
            tag = Some(arg.clone());
        }
        index += 1;
    }
    let tag = tag.ok_or_else(|| Error::Message("a host tag is required".into()))?;
    let key = key.ok_or_else(|| Error::Message("--key is required".into()))?;
    let hostname = hostname.ok_or_else(|| Error::Message("--hostname is required".into()))?;
    validate_tag(&key)?;
    validate_hostname(&hostname)?;
    if let Some(user) = &user {
        validate_user(user)?;
    }
    Ok(HostInput {
        tag,
        key,
        hostname,
        user,
        port,
        timeout,
        options,
    })
}

fn parse_connect(args: &[String]) -> Result<(&str, Vec<String>)> {
    if args.is_empty() {
        return Err(Error::Message(
            "usage: hdnfs <volume> ssh connect <tag> [-- <ssh options>]".into(),
        ));
    }
    validate_tag(&args[0])?;
    if args.len() == 1 {
        return Ok((&args[0], Vec::new()));
    }
    if args[1] != "--" {
        return Err(Error::Message(
            "ssh options must follow --\nusage: hdnfs <volume> ssh connect <tag> [-- <ssh options>]"
                .into(),
        ));
    }
    Ok((&args[0], args[2..].to_vec()))
}

fn split_flag(name: &str) -> (&str, Option<&str>) {
    match name.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (name, None),
    }
}

fn flag_value(
    args: &[String],
    index: &mut usize,
    inline: Option<&str>,
    flag: &str,
) -> Result<String> {
    if let Some(value) = inline {
        return Ok(value.to_string());
    }
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| Error::Message(format!("{flag} needs a value")))
}

fn assign_once(slot: &mut Option<String>, value: String, flag: &str) -> Result<()> {
    if slot.is_some() {
        return Err(Error::Message(format!("{flag} is already set")));
    }
    *slot = Some(value);
    Ok(())
}

pub fn reject_extra(args: &[String]) -> Result<()> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-i" || arg.starts_with("-i/") || arg.starts_with("-i=") {
            return Err(Error::Denied(
                "connect does not accept another identity file".into(),
            ));
        }
        if arg == "-o" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| Error::Message("ssh option -o needs a value".into()))?;
            reject_option_assignment(value)?;
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("-o") {
            if !value.is_empty() {
                reject_option_assignment(value)?;
            }
        }
        index += 1;
    }
    Ok(())
}

fn reject_option_assignment(value: &str) -> Result<()> {
    let keyword = value.split([' ', '=']).next().unwrap_or("").trim();
    if forbidden_keyword(keyword) {
        return Err(Error::Denied(format!("ssh option {keyword} is reserved")));
    }
    Ok(())
}

/// Volume directory for keys, hosts, and passwords.
pub(crate) const DRIVE_DIR: &str = "/.drive";

fn key_dir(tag: &str) -> String {
    format!("{DRIVE_DIR}/keys/{tag}")
}

pub(crate) fn private_path(tag: &str) -> String {
    format!("{DRIVE_DIR}/keys/{tag}/private")
}

pub(crate) fn meta_path(tag: &str) -> String {
    format!("{DRIVE_DIR}/keys/{tag}/meta")
}

pub(crate) fn host_path(tag: &str) -> String {
    format!("{DRIVE_DIR}/hosts/{tag}")
}

fn password_path(tag: &str) -> String {
    format!("{DRIVE_DIR}/passwords/{tag}")
}

fn exists(volume: &mut Volume, path: &str) -> Result<bool> {
    match volume.stat(Some(path)) {
        Ok(_) => Ok(true),
        Err(Error::NotFound(_)) => Ok(false),
        Err(err) => Err(err),
    }
}

fn entries(volume: &mut Volume, path: &str) -> Result<Vec<hdnfs::DirEntry>> {
    match volume.list(path) {
        Ok(entries) => Ok(entries),
        Err(Error::NotFound(_)) => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

pub fn create_key(volume: &mut Volume, tag: &str, comment: Option<&str>) -> Result<PublicInfo> {
    validate_tag(tag)?;
    reject_password_tag(volume, tag)?;
    if key_exists(volume, tag)? {
        return Err(Error::AlreadyExists(format!("key {tag}")));
    }
    let comment = match comment {
        Some(comment) => {
            validate_comment(comment)?;
            comment.to_string()
        }
        None => format!("hdnfs:{tag}"),
    };
    let mut private =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .map_err(|err| Error::Message(format!("key generation failed: {err}")))?;
    private.set_comment(&comment);
    let public = private
        .public_key()
        .to_openssh()
        .map_err(|err| Error::Message(format!("failed to encode public key: {err}")))?;
    let pem = private
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|err| Error::Message(format!("failed to encode private key: {err}")))?;
    store_key(volume, tag, pem.as_bytes(), Some(&public))?;
    inspect_public(&public)
}

pub fn add_key(volume: &mut Volume, tag: &str, file: &Path) -> Result<Option<PublicInfo>> {
    validate_tag(tag)?;
    reject_password_tag(volume, tag)?;
    if key_exists(volume, tag)? {
        return Err(Error::AlreadyExists(format!("key {tag}")));
    }
    let mut bytes =
        std::fs::read(file).map_err(|err| Error::Message(format!("{}: {err}", file.display())))?;
    if bytes.is_empty() {
        return Err(Error::Message("key file is empty".into()));
    }
    if bytes.len() > MAX_PRIVATE {
        bytes.zeroize();
        return Err(Error::Message("key file is larger than 256 KiB".into()));
    }
    // Stored unchanged. A public line is recorded when the file yields one.
    let info = public_line_from_private(&bytes);
    let stored = store_key(
        volume,
        tag,
        &bytes,
        info.as_ref().map(|info| info.line.as_str()),
    );
    bytes.zeroize();
    stored?;
    Ok(info)
}

fn public_line_from_private(bytes: &[u8]) -> Option<PublicInfo> {
    if let Some(info) = info_from_parsed_private(bytes) {
        return Some(info);
    }
    // ssh-key rejects some OpenSSH ECDSA private scalars. The scalar is an
    // mpint, so a leading 0x00 is omitted, and EcdsaPrivateKey<N> accepts
    // only N bytes or N+1 with one leading zero. A P-521 scalar is 66 bytes
    // and is often stored as 65. The public key and the comment are still
    // in the file, and the private bytes stay as they were.
    info_from_openssh_public(bytes)
}

fn info_from_parsed_private(bytes: &[u8]) -> Option<PublicInfo> {
    let key = ssh_key::PrivateKey::from_openssh(bytes).ok()?;
    let line = key.public_key().to_openssh().ok()?;
    inspect_public(&line).ok()
}

fn info_from_openssh_public(bytes: &[u8]) -> Option<PublicInfo> {
    let decoded = decode_openssh_container(bytes)?;
    let mut off = OPENSSH_MAGIC.len();
    let cipher = take_ssh_string(&decoded, &mut off)?;
    let _kdf = take_ssh_string(&decoded, &mut off)?;
    let _kdf_options = take_ssh_string(&decoded, &mut off)?;
    let nkeys = take_u32(&decoded, &mut off)?;
    if nkeys != 1 {
        return None;
    }
    let public_blob = take_ssh_string(&decoded, &mut off)?;
    let private_blob = take_ssh_string(&decoded, &mut off)?;
    let key = ssh_key::PublicKey::from_bytes(public_blob).ok()?;
    let comment = if cipher == b"none" {
        openssh_unencrypted_comment(private_blob)
    } else {
        None
    };
    finish_public_info(key, comment.as_deref())
}

fn finish_public_info(mut key: ssh_key::PublicKey, comment: Option<&str>) -> Option<PublicInfo> {
    if let Some(comment) = comment {
        if !comment.is_empty() && !comment.chars().any(|ch| ch.is_control()) {
            key.set_comment(comment);
            if let Some(info) = public_key_info(&key) {
                return Some(info);
            }
            key.set_comment("");
        }
    }
    public_key_info(&key)
}

fn public_key_info(key: &ssh_key::PublicKey) -> Option<PublicInfo> {
    let line = key.to_openssh().ok()?;
    inspect_public(&line).ok()
}

const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

fn decode_openssh_container(bytes: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if bytes.starts_with(OPENSSH_MAGIC) {
        return Some(Zeroizing::new(bytes.to_vec()));
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let body = openssh_pem_body(text)?;
    let decoded = Zeroizing::new(base64_decode(&body)?);
    if decoded.starts_with(OPENSSH_MAGIC) {
        Some(decoded)
    } else {
        None
    }
}

fn openssh_pem_body(text: &str) -> Option<String> {
    let mut inside = false;
    let mut body = String::new();
    for line in text.lines() {
        let line = line.trim();
        if !inside {
            if line == "-----BEGIN OPENSSH PRIVATE KEY-----" {
                inside = true;
            }
            continue;
        }
        if line == "-----END OPENSSH PRIVATE KEY-----" {
            return if body.is_empty() { None } else { Some(body) };
        }
        if line.is_empty() || line.starts_with("Proc-Type:") || line.starts_with("DEK-Info:") {
            continue;
        }
        body.push_str(line);
    }
    None
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let filtered: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if filtered.is_empty() || filtered.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(filtered.len() / 4 * 3);
    for chunk in filtered.chunks_exact(4) {
        let mut pads = 0usize;
        let mut acc = 0u32;
        for (index, byte) in chunk.iter().copied().enumerate() {
            if byte == b'=' {
                if index < 2 || chunk[index..].iter().any(|item| *item != b'=') {
                    return None;
                }
                pads += 1;
                acc <<= 6;
                continue;
            }
            if pads != 0 {
                return None;
            }
            acc = (acc << 6) | u32::from(value(byte)?);
        }
        let nbytes = 3 - pads;
        for shift in [16u32, 8, 0].into_iter().take(nbytes) {
            out.push((acc >> shift) as u8);
        }
    }
    Some(out)
}

fn openssh_unencrypted_comment(private_blob: &[u8]) -> Option<String> {
    let mut off = 0;
    let first = take_u32(private_blob, &mut off)?;
    let second = take_u32(private_blob, &mut off)?;
    if first != second {
        return None;
    }
    let algorithm = take_ssh_string(private_blob, &mut off)?;
    let algorithm = std::str::from_utf8(algorithm).ok()?;
    off = skip_private_fields(private_blob, off, algorithm)?;
    let comment = take_ssh_string(private_blob, &mut off)?;
    let comment = std::str::from_utf8(comment).ok()?.to_string();
    if comment.chars().any(|ch| ch.is_control()) {
        None
    } else {
        Some(comment)
    }
}

/// Skip the private-key fields that follow the algorithm string.
/// The comment is the next string.
fn skip_private_fields(buf: &[u8], off: usize, algorithm: &str) -> Option<usize> {
    match algorithm {
        "ssh-ed25519" => skip_ssh_strings(buf, off, 2),
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            skip_ssh_strings(buf, off, 3)
        }
        "ssh-rsa" => skip_ssh_strings(buf, off, 6),
        "ssh-dss" => skip_ssh_strings(buf, off, 5),
        "sk-ssh-ed25519@openssh.com" => {
            let off = skip_ssh_strings(buf, off, 2)?;
            skip_ssh_strings(buf, off.checked_add(1)?, 2)
        }
        "sk-ecdsa-sha2-nistp256@openssh.com" => {
            let off = skip_ssh_strings(buf, off, 3)?;
            skip_ssh_strings(buf, off.checked_add(1)?, 2)
        }
        _ => None,
    }
}

fn skip_ssh_strings(buf: &[u8], mut off: usize, count: usize) -> Option<usize> {
    for _ in 0..count {
        if off > buf.len() {
            return None;
        }
        let _ = take_ssh_string(buf, &mut off)?;
    }
    Some(off)
}

fn take_u32(buf: &[u8], off: &mut usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > buf.len() {
        return None;
    }
    let value = u32::from_be_bytes(buf[*off..end].try_into().ok()?);
    *off = end;
    Some(value)
}

fn take_ssh_string<'a>(buf: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
    let len = take_u32(buf, off)? as usize;
    let end = off.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let value = &buf[*off..end];
    *off = end;
    Some(value)
}

fn key_exists(volume: &mut Volume, tag: &str) -> Result<bool> {
    Ok(exists(volume, &private_path(tag))? || exists(volume, &meta_path(tag))?)
}

fn store_key(volume: &mut Volume, tag: &str, private: &[u8], public: Option<&str>) -> Result<()> {
    let public = match public {
        Some(line) => {
            let line = line.trim_end_matches(['\n', '\r']).to_string();
            if line.is_empty() || line.len() > MAX_PUBLIC || line.chars().any(|ch| ch.is_control())
            {
                return Err(Error::Message("public key line is not usable".into()));
            }
            Some(line)
        }
        None => None,
    };
    let meta = KeyMeta { version: 1, public };
    let encoded = serde_json::to_vec_pretty(&meta)
        .map_err(|err| Error::Message(format!("failed to encode key metadata: {err}")))?;
    volume.write_bytes(&private_path(tag), private)?;
    if let Err(err) = volume.write_bytes(&meta_path(tag), &encoded) {
        let _ = volume.delete(&private_path(tag));
        let _ = volume.delete(&key_dir(tag));
        return Err(err);
    }
    Ok(())
}

pub fn delete_key(volume: &mut Volume, tag: &str) -> Result<()> {
    validate_tag(tag)?;
    let users = hosts_using(volume, tag)?;
    if !users.is_empty() {
        return Err(Error::Denied(format!(
            "key {tag} is used by {}",
            users.join(", ")
        )));
    }
    let dir = key_dir(tag);
    let has_dir = exists(volume, &dir)?;
    let has_private = exists(volume, &private_path(tag))?;
    let has_meta = exists(volume, &meta_path(tag))?;
    if !has_dir && !has_private && !has_meta {
        return Err(Error::NotFound(format!("key {tag}")));
    }
    if has_private {
        volume.delete(&private_path(tag))?;
    }
    if has_meta {
        volume.delete(&meta_path(tag))?;
    }
    if exists(volume, &dir)? {
        volume.delete(&dir)?;
    }
    Ok(())
}

pub fn list_keys(volume: &mut Volume) -> Result<Vec<KeyRow>> {
    let mut rows = Vec::new();
    let mut names = entries(volume, &format!("{DRIVE_DIR}/keys"))?;
    names.sort_by(|left, right| left.name.cmp(&right.name));
    for entry in names {
        if entry.kind != Kind::Dir {
            rows.push(KeyRow {
                tag: entry.name,
                detail: KeyDetail::Invalid,
            });
            continue;
        }
        rows.push(KeyRow {
            tag: entry.name.clone(),
            detail: match describe_key(volume, &entry.name) {
                Ok(Some(info)) => KeyDetail::Ready(info),
                Ok(None) => KeyDetail::Raw,
                Err(Error::NotFound(_)) => KeyDetail::Incomplete,
                Err(_) => KeyDetail::Invalid,
            },
        });
    }
    Ok(rows)
}

pub fn format_key_row(row: &KeyRow) -> String {
    match &row.detail {
        KeyDetail::Ready(info) => format!(
            "{}  {}  {}  {}",
            row.tag, info.algorithm, info.fingerprint, info.comment
        ),
        KeyDetail::Raw => row.tag.clone(),
        KeyDetail::Incomplete => format!("{}  incomplete", row.tag),
        KeyDetail::Invalid => format!("{}  invalid", row.tag),
    }
}

/// Writes one OpenSSH public line derived from the stored private key.
/// An existing destination is left unchanged.
#[cfg(test)]
pub fn write_public_key(volume: &mut Volume, tag: &str, dest: &Path) -> Result<()> {
    validate_tag(tag)?;
    if dest.as_os_str().is_empty() {
        return Err(Error::Message("empty input".into()));
    }
    let info = public_from_private(volume, tag)?;
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(Error::Message(format!(
                "{} is not a directory",
                parent.display()
            )));
        }
    }
    ensure_new_path(dest)?;
    let body = format!("{}\n", info.line);
    write_new_file(dest, body.as_bytes(), 0o644)
}

#[derive(Debug)]
pub struct ExportedKey {
    pub private_path: std::path::PathBuf,
    pub public_path: Option<std::path::PathBuf>,
}

/// Copies a stored key into `dir` as `<tag>` and, when the file yields one, `<tag>.pub`.
/// The private file is the stored bytes, mode 0600. An existing file is left unchanged.
pub fn export_key(volume: &mut Volume, tag: &str, dir: &Path) -> Result<ExportedKey> {
    validate_tag(tag)?;
    require_directory(dir)?;
    let private_path_in_volume = private_path(tag);
    if !exists(volume, &private_path_in_volume)? {
        return Err(Error::NotFound(format!("key {tag}")));
    }
    let bytes = volume.read_bytes(&private_path_in_volume)?;
    let public = public_line_from_private(&bytes);
    let private_dest = dir.join(tag);
    let public_dest = dir.join(format!("{tag}.pub"));
    ensure_new_path(&private_dest)?;
    if public.is_some() {
        ensure_new_path(&public_dest)?;
    }
    write_new_file(&private_dest, &bytes, 0o600)?;
    let Some(info) = public else {
        return Ok(ExportedKey {
            private_path: private_dest,
            public_path: None,
        });
    };
    let body = format!("{}\n", info.line);
    if let Err(err) = write_new_file(&public_dest, body.as_bytes(), 0o644) {
        let _ = std::fs::remove_file(&private_dest);
        return Err(err);
    }
    Ok(ExportedKey {
        private_path: private_dest,
        public_path: Some(public_dest),
    })
}

fn require_directory(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() {
        return Err(Error::Message("empty input".into()));
    }
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => match std::fs::metadata(dir) {
            Ok(target) if target.is_dir() => Ok(()),
            Ok(_) => Err(Error::Message(format!(
                "{} is not a directory",
                dir.display()
            ))),
            Err(_) => Err(Error::Message(format!("{} is a symlink", dir.display()))),
        },
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(Error::Message(format!(
            "{} is not a directory",
            dir.display()
        ))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            Err(Error::Message(format!("{} does not exist", dir.display())))
        }
        Err(err) => Err(Error::Message(format!("{}: {err}", dir.display()))),
    }
}

fn ensure_new_path(dest: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dest) {
        Ok(meta) if meta.is_dir() => {
            Err(Error::Message(format!("{} is a directory", dest.display())))
        }
        Ok(_) => Err(Error::Message(format!("{} already exists", dest.display()))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(Error::Message(format!("{}: {err}", dest.display()))),
    }
}

fn write_new_file(dest: &Path, body: &[u8], mode: u32) -> Result<()> {
    let tmp = partial_public_path(dest);
    let mut partial = RemovePartial(Some(tmp.clone()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|err| Error::Message(format!("{}: {err}", tmp.display())))?;
    if let Err(err) = file.write_all(body).and_then(|_| file.sync_all()) {
        return Err(Error::Message(format!("{}: {err}", dest.display())));
    }
    drop(file);
    std::fs::rename(&tmp, dest)
        .map_err(|err| Error::Message(format!("{}: {err}", dest.display())))?;
    partial.0 = None;
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode))
        .map_err(|err| Error::Message(format!("{}: {err}", dest.display())))?;
    Ok(())
}

struct RemovePartial(Option<std::path::PathBuf>);

impl Drop for RemovePartial {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn partial_public_path(dest: &Path) -> std::path::PathBuf {
    let mut name = dest
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("key.pub"));
    let n = rand::random::<u32>();
    name.push(format!(".hdnfs-partial-{n}"));
    dest.with_file_name(name)
}

#[cfg(test)]
fn public_from_private(volume: &mut Volume, tag: &str) -> Result<PublicInfo> {
    let path = private_path(tag);
    if !exists(volume, &path)? {
        return Err(Error::NotFound(format!("key {tag}")));
    }
    // The public line comes from these bytes, not from the copy stored in meta.
    let bytes = volume.read_bytes(&path)?;
    public_line_from_private(&bytes)
        .ok_or_else(|| Error::Message(format!("key {tag} did not yield a public line")))
}

pub fn key_info(volume: &mut Volume, tag: &str) -> Result<String> {
    validate_tag(tag)?;
    let info = describe_key(volume, tag)?;
    let (created, modified) = node_times(volume, &meta_path(tag))?;
    let created = format_unix_utc(created);
    let modified = format_unix_utc(modified);
    Ok(match info {
        Some(info) => format!(
            "\
tag: {tag}
algorithm: {algorithm}
fingerprint: {fingerprint}
comment: {comment}
created: {created}
modified: {modified}
public: {public}
",
            algorithm = info.algorithm,
            fingerprint = info.fingerprint,
            comment = info.comment,
            public = info.line,
        ),
        None => format!(
            "\
tag: {tag}
created: {created}
modified: {modified}
"
        ),
    })
}

/// Meta's public line when it has one. Otherwise the line carried in the
/// stored private file. An older add left that line out for keys ssh-key
/// could not decode.
fn describe_key(volume: &mut Volume, tag: &str) -> Result<Option<PublicInfo>> {
    match read_meta(volume, tag)? {
        Some(info) => Ok(Some(info)),
        None => {
            let path = private_path(tag);
            if !exists(volume, &path)? {
                return Ok(None);
            }
            let bytes = volume.read_bytes(&path)?;
            Ok(public_line_from_private(&bytes))
        }
    }
}

fn read_meta(volume: &mut Volume, tag: &str) -> Result<Option<PublicInfo>> {
    let path = meta_path(tag);
    if !exists(volume, &path)? {
        return Err(Error::NotFound(format!("key {tag}")));
    }
    let bytes = volume.read_bytes(&path)?;
    let meta: KeyMeta = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Message(format!("key {tag} metadata is invalid")))?;
    if meta.version != 1 {
        return Err(Error::Message(format!(
            "key {tag} metadata version {} is not supported",
            meta.version
        )));
    }
    match meta.public.as_deref() {
        Some(line) => Ok(Some(inspect_public(line)?)),
        None => Ok(None),
    }
}

pub fn inspect_public(line: &str) -> Result<PublicInfo> {
    let trimmed = line.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() || trimmed.len() > MAX_PUBLIC || trimmed.chars().any(|ch| ch.is_control())
    {
        return Err(Error::Message("public key line is not usable".into()));
    }
    let key = ssh_key::PublicKey::from_openssh(trimmed)
        .map_err(|err| Error::Message(format!("public key line is not usable: {err}")))?;
    let algorithm = key.algorithm().to_string();
    let algorithm = algorithm
        .strip_prefix("ssh-")
        .unwrap_or(&algorithm)
        .to_string();
    Ok(PublicInfo {
        algorithm,
        fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        comment: key.comment().to_string(),
        line: trimmed.to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRow {
    pub tag: String,
    /// Character count. Empty when the stored file cannot be read.
    pub length: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordFile {
    version: u32,
    password: String,
}

const PASSWORD_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub fn validate_stored_password(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(Error::Message("password is empty".into()));
    }
    if password.len() > 1024 {
        return Err(Error::Message("password must be at most 1024 bytes".into()));
    }
    if password.chars().any(|ch| ch.is_control()) {
        return Err(Error::Message(
            "password cannot contain control characters".into(),
        ));
    }
    Ok(())
}

pub fn parse_password_length(text: &str) -> Result<usize> {
    let length: usize = text
        .trim()
        .parse()
        .map_err(|_| Error::Message("length must be 8 to 128".into()))?;
    if (8..=128).contains(&length) {
        Ok(length)
    } else {
        Err(Error::Message("length must be 8 to 128".into()))
    }
}

pub fn parse_yes_no(text: &str) -> Result<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Err(Error::Message("answer y or n".into())),
    }
}

pub fn password_tag_available(volume: &mut Volume, tag: &str) -> Result<()> {
    validate_tag(tag)?;
    if password_exists(volume, tag)? {
        return Err(Error::AlreadyExists(format!("password {tag}")));
    }
    if key_exists(volume, tag)? {
        return Err(Error::AlreadyExists(format!("key {tag}")));
    }
    if exists(volume, &host_path(tag))? {
        return Err(Error::AlreadyExists(format!("host {tag}")));
    }
    Ok(())
}

pub fn add_password(volume: &mut Volume, tag: &str, password: &str) -> Result<()> {
    password_tag_available(volume, tag)?;
    validate_stored_password(password)?;
    store_password(volume, tag, password)
}

pub fn generate_password(length: usize, symbols: bool) -> Result<Zeroizing<String>> {
    if !(8..=128).contains(&length) {
        return Err(Error::Message("length must be 8 to 128".into()));
    }
    let alphabet = password_alphabet(symbols);
    let mut rng = rand::rngs::OsRng;
    let mut out = String::with_capacity(length);
    for _ in 0..length {
        let index = rng.gen_range(0..alphabet.len());
        out.push(alphabet[index] as char);
    }
    Ok(Zeroizing::new(out))
}

pub fn generate_password_record(
    volume: &mut Volume,
    tag: &str,
    length: usize,
    symbols: bool,
) -> Result<()> {
    let secret = generate_password(length, symbols)?;
    add_password(volume, tag, &secret)?;
    if let Err(err) = copy_secret(&secret) {
        return Err(Error::Message(format!("saved password {tag}, but {err}")));
    }
    Ok(())
}

pub fn list_passwords(volume: &mut Volume) -> Result<Vec<PasswordRow>> {
    let mut rows = Vec::new();
    let mut names = entries(volume, &format!("{DRIVE_DIR}/passwords"))?;
    names.sort_by(|left, right| left.name.cmp(&right.name));
    for entry in names {
        if entry.kind != Kind::File {
            rows.push(PasswordRow {
                tag: entry.name,
                length: None,
            });
            continue;
        }
        let length = match read_password(volume, &entry.name) {
            Ok(secret) => Some(secret.chars().count()),
            Err(_) => None,
        };
        rows.push(PasswordRow {
            tag: entry.name,
            length,
        });
    }
    Ok(rows)
}

pub fn format_password_row(row: &PasswordRow) -> String {
    match row.length {
        Some(length) => format!("{}  {length}", row.tag),
        None => format!("{}  invalid", row.tag),
    }
}

pub fn delete_password(volume: &mut Volume, tag: &str) -> Result<()> {
    validate_tag(tag)?;
    let path = password_path(tag);
    if !exists(volume, &path)? {
        return Err(Error::NotFound(format!("password {tag}")));
    }
    volume.delete(&path)?;
    Ok(())
}

pub fn copy_password(volume: &mut Volume, tag: &str) -> Result<()> {
    validate_tag(tag)?;
    let secret = read_password(volume, tag)?;
    copy_secret(&secret)
}

pub fn copy_secret(text: &str) -> Result<()> {
    #[cfg(test)]
    {
        COPIED.with(|slot| {
            slot.replace(Some(text.to_string()));
        });
        return Ok(());
    }
    #[cfg(not(test))]
    {
        copy_secret_live(text)
    }
}

#[cfg(test)]
thread_local! {
    static COPIED: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub fn take_copied() -> Option<String> {
    COPIED.with(|slot| slot.replace(None))
}

#[cfg(not(test))]
fn copy_secret_live(text: &str) -> Result<()> {
    let tool = copy_with_tool(text);
    let osc = write_osc52(text);
    if tool || osc {
        Ok(())
    } else {
        Err(Error::Message("clipboard is not available".into()))
    }
}

#[cfg(not(test))]
fn copy_with_tool(text: &str) -> bool {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() && run_clipboard("wl-copy", &[], text) {
        return true;
    }
    if std::env::var_os("DISPLAY").is_some()
        && (run_clipboard("xclip", &["-selection", "clipboard"], text)
            || run_clipboard("xsel", &["--clipboard", "--input"], text))
    {
        return true;
    }
    false
}

#[cfg(not(test))]
fn run_clipboard(program: &str, args: &[&str], text: &str) -> bool {
    let Ok(mut child) = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    let Some(mut stdin) = child.stdin.take() else {
        return false;
    };
    if stdin.write_all(text.as_bytes()).is_err() {
        return false;
    }
    drop(stdin);
    child.wait().map(|status| status.success()).unwrap_or(false)
}

#[cfg(not(test))]
fn write_osc52(text: &str) -> bool {
    let payload = format!("\x1b]52;c;{}\x07", base64_encode(text.as_bytes()));
    let Ok(mut tty) = OpenOptions::new().write(true).open("/dev/tty") else {
        return false;
    };
    tty.write_all(payload.as_bytes()).is_ok() && tty.flush().is_ok()
}

#[cfg(not(test))]
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        let bits =
            ((data[index] as u32) << 16) | ((data[index + 1] as u32) << 8) | data[index + 2] as u32;
        out.push(TABLE[((bits >> 18) & 63) as usize] as char);
        out.push(TABLE[((bits >> 12) & 63) as usize] as char);
        out.push(TABLE[((bits >> 6) & 63) as usize] as char);
        out.push(TABLE[(bits & 63) as usize] as char);
        index += 3;
    }
    let rest = data.len() - index;
    if rest == 1 {
        let bits = (data[index] as u32) << 16;
        out.push(TABLE[((bits >> 18) & 63) as usize] as char);
        out.push(TABLE[((bits >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rest == 2 {
        let bits = ((data[index] as u32) << 16) | ((data[index + 1] as u32) << 8);
        out.push(TABLE[((bits >> 18) & 63) as usize] as char);
        out.push(TABLE[((bits >> 12) & 63) as usize] as char);
        out.push(TABLE[((bits >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

fn password_alphabet(symbols: bool) -> &'static [u8] {
    if symbols {
        PASSWORD_SYMBOLS_FULL
    } else {
        PASSWORD_ALPHABET
    }
}

const PASSWORD_SYMBOLS_FULL: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";

fn password_exists(volume: &mut Volume, tag: &str) -> Result<bool> {
    exists(volume, &password_path(tag))
}

fn reject_password_tag(volume: &mut Volume, tag: &str) -> Result<()> {
    if password_exists(volume, tag)? {
        return Err(Error::AlreadyExists(format!("password {tag}")));
    }
    Ok(())
}

fn store_password(volume: &mut Volume, tag: &str, password: &str) -> Result<()> {
    let file = PasswordFile {
        version: 1,
        password: password.to_string(),
    };
    let mut encoded = serde_json::to_vec(&file)
        .map_err(|err| Error::Message(format!("failed to encode password: {err}")))?;
    let mut owned = file.password;
    owned.zeroize();
    let result = volume.write_bytes(&password_path(tag), &encoded);
    encoded.zeroize();
    result?;
    Ok(())
}

fn read_password(volume: &mut Volume, tag: &str) -> Result<Zeroizing<String>> {
    let path = password_path(tag);
    if !exists(volume, &path)? {
        return Err(Error::NotFound(format!("password {tag}")));
    }
    let bytes = volume.read_bytes(&path)?;
    let mut text = String::from_utf8(bytes.to_vec())
        .map_err(|_| Error::Message(format!("password {tag} is invalid")))?;
    let file: PasswordFile = match serde_json::from_str(&text) {
        Ok(file) => file,
        Err(_) => {
            text.zeroize();
            return Err(Error::Message(format!("password {tag} is invalid")));
        }
    };
    text.zeroize();
    if file.version != 1 {
        return Err(Error::Message(format!(
            "password {tag} version {} is not supported",
            file.version
        )));
    }
    validate_stored_password(&file.password)?;
    Ok(Zeroizing::new(file.password))
}

pub fn create_host(volume: &mut Volume, input: &HostInput) -> Result<()> {
    validate_tag(&input.tag)?;
    if exists(volume, &host_path(&input.tag))? {
        return Err(Error::AlreadyExists(format!("host {}", input.tag)));
    }
    reject_password_tag(volume, &input.tag)?;
    write_host(volume, input)
}

pub fn update_host(volume: &mut Volume, input: &HostInput) -> Result<()> {
    validate_tag(&input.tag)?;
    if !exists(volume, &host_path(&input.tag))? {
        return Err(Error::NotFound(format!("host {}", input.tag)));
    }
    write_host(volume, input)
}

fn write_host(volume: &mut Volume, input: &HostInput) -> Result<()> {
    if !exists(volume, &meta_path(&input.key))? {
        return Err(Error::NotFound(format!("key {}", input.key)));
    }
    let record = HostRecord {
        key: input.key.clone(),
        hostname: input.hostname.clone(),
        user: input.user.clone(),
        port: input.port,
        timeout: input.timeout,
        options: input.options.clone(),
    };
    validate_host(&record)?;
    let file = HostFile {
        version: 1,
        key: record.key,
        hostname: record.hostname,
        user: record.user,
        port: record.port,
        timeout: record.timeout,
        options: record.options,
    };
    let encoded = serde_json::to_vec_pretty(&file)
        .map_err(|err| Error::Message(format!("failed to encode host: {err}")))?;
    volume.write_bytes(&host_path(&input.tag), &encoded)?;
    Ok(())
}

pub fn delete_host(volume: &mut Volume, tag: &str) -> Result<()> {
    validate_tag(tag)?;
    let path = host_path(tag);
    if !exists(volume, &path)? {
        return Err(Error::NotFound(format!("host {tag}")));
    }
    volume.delete(&path)
}

pub fn list_hosts(volume: &mut Volume) -> Result<Vec<HostRow>> {
    let mut rows = Vec::new();
    let mut names = entries(volume, &format!("{DRIVE_DIR}/hosts"))?;
    names.sort_by(|left, right| left.name.cmp(&right.name));
    for entry in names {
        if entry.kind != Kind::File {
            return Err(Error::Message(format!(
                "{DRIVE_DIR}/hosts/{} is not a file",
                entry.name
            )));
        }
        let host = load_host(volume, &entry.name)?;
        rows.push(HostRow {
            tag: entry.name,
            target: target_of(&host),
            key: host.key,
        });
    }
    Ok(rows)
}

pub fn format_host_row(row: &HostRow) -> String {
    format!("{}  {}  {}", row.tag, row.target, row.key)
}

pub fn host_info(volume: &mut Volume, tag: &str) -> Result<String> {
    validate_tag(tag)?;
    let host = load_host(volume, tag)?;
    Ok(format_host_info(tag, &host))
}

pub fn format_host_info(tag: &str, host: &HostRecord) -> String {
    let mut text = format!(
        "tag: {tag}\nkey: {}\nhostname: {}\n",
        host.key, host.hostname
    );
    if let Some(user) = &host.user {
        text.push_str(&format!("user: {user}\n"));
    }
    if let Some(port) = host.port {
        text.push_str(&format!("port: {port}\n"));
    }
    if let Some(timeout) = host.timeout {
        text.push_str(&format!("timeout: {timeout}\n"));
    }
    if !host.options.is_empty() {
        text.push_str("options:\n");
        for option in &host.options {
            text.push_str(&format!("  {option}\n"));
        }
    }
    text.push_str("config:\n");
    text.push_str(&render_config(host));
    text
}

pub fn target_of(host: &HostRecord) -> String {
    let mut text = String::new();
    if let Some(user) = &host.user {
        text.push_str(user);
        text.push('@');
    }
    text.push_str(&host.hostname);
    if let Some(port) = host.port {
        text.push(':');
        text.push_str(&port.to_string());
    }
    text
}

pub fn load_host(volume: &mut Volume, tag: &str) -> Result<HostRecord> {
    let path = host_path(tag);
    if !exists(volume, &path)? {
        return Err(Error::NotFound(format!("host {tag}")));
    }
    let bytes = volume.read_bytes(&path)?;
    let file: HostFile = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Message(format!("host {tag} is invalid")))?;
    if file.version != 1 {
        return Err(Error::Message(format!(
            "host {tag} version {} is not supported",
            file.version
        )));
    }
    let record = HostRecord {
        key: file.key,
        hostname: file.hostname,
        user: file.user,
        port: file.port,
        timeout: file.timeout,
        options: file.options,
    };
    validate_host(&record)?;
    Ok(record)
}

fn validate_host(host: &HostRecord) -> Result<()> {
    validate_tag(&host.key)?;
    validate_hostname(&host.hostname)?;
    if let Some(user) = &host.user {
        validate_user(user)?;
    }
    if let Some(0) = host.port {
        return Err(Error::Message("port must be from 1 to 65535".into()));
    }
    if let Some(timeout) = host.timeout {
        if !(1..=3600).contains(&timeout) {
            return Err(Error::Message(
                "timeout must be from 1 to 3600 seconds".into(),
            ));
        }
    }
    if host.options.len() > MAX_OPTIONS {
        return Err(Error::Message("a host can have at most 64 options".into()));
    }
    for option in &host.options {
        validate_option_line(option)?;
    }
    Ok(())
}

fn hosts_using(volume: &mut Volume, key_tag: &str) -> Result<Vec<String>> {
    let mut found = Vec::new();
    let names = entries(volume, &format!("{DRIVE_DIR}/hosts"))?;
    for entry in names {
        if entry.kind != Kind::File {
            return Err(Error::Message(format!(
                "{DRIVE_DIR}/hosts/{} is not a file",
                entry.name
            )));
        }
        let host = load_host(volume, &entry.name)?;
        if host.key == key_tag {
            found.push(entry.name);
        }
    }
    found.sort();
    Ok(found)
}

fn node_times(volume: &mut Volume, path: &str) -> Result<(i64, i64)> {
    match volume.stat(Some(path))? {
        Stat::Node {
            created, modified, ..
        } => Ok((created, modified)),
        Stat::Volume { .. } => Err(Error::Message(format!("{path} is not a file"))),
    }
}

pub fn render_config(host: &HostRecord) -> String {
    let mut text = format!("Host hdnfs\n  HostName {}\n", host.hostname);
    if let Some(user) = &host.user {
        text.push_str(&format!("  User {user}\n"));
    }
    if let Some(port) = host.port {
        text.push_str(&format!("  Port {port}\n"));
    }
    if let Some(timeout) = host.timeout {
        text.push_str(&format!("  ConnectTimeout {timeout}\n"));
    }
    for option in &host.options {
        text.push_str(&format!("  {option}\n"));
    }
    text
}

pub fn load_session(volume: &mut Volume, tag: &str) -> Result<Session> {
    disable_core_dumps()?;
    validate_tag(tag)?;
    let host = load_host(volume, tag)?;
    if !exists(volume, &meta_path(&host.key))? {
        return Err(Error::NotFound(format!("key {}", host.key)));
    }
    let path = private_path(&host.key);
    if !exists(volume, &path)? {
        return Err(Error::NotFound(format!("key {}", host.key)));
    }
    let private_key = volume.read_bytes(&path)?;
    Ok(Session {
        config: render_config(&host),
        private_key,
    })
}

pub fn ssh_argv(
    key_fd: RawFd,
    config_fd: RawFd,
    ready_fd: Option<RawFd>,
    extra: &[String],
) -> Result<Vec<String>> {
    reject_extra(extra)?;
    let pid = std::process::id();
    // OpenSSH samples the terminal and requests the remote pty only after
    // LocalCommand returns. The TUI passes a pipe read end and closes the
    // write end once the startup termios are restored, so the remote shell
    // does not inherit raw mode.
    let local = match ready_fd {
        Some(fd) => format!("kill -USR1 {pid} && cat /proc/{pid}/fd/{fd} >/dev/null"),
        None => format!("kill -USR1 {pid}"),
    };
    let mut args = vec![
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-i".into(),
        format!("/proc/{pid}/fd/{key_fd}"),
        "-o".into(),
        "PermitLocalCommand=yes".into(),
        "-o".into(),
        format!("LocalCommand={local}"),
        "-F".into(),
        format!("/proc/{pid}/fd/{config_fd}"),
    ];
    args.extend(extra.iter().cloned());
    args.push("hdnfs".into());
    Ok(args)
}

pub fn run_session(session: Session, extra: &[String]) -> Result<SshStatus> {
    let mut child = SshProc::spawn(session, extra, false)?;
    child.take_terminal();
    child.wait_done()
}

/// `ssh` while the TUI still owns the screen.
///
/// `NeedsTerminal` means `ssh` stopped for a prompt before authentication, so
/// the host-key question has to be answered and a failure still belongs to the
/// TUI. `Authenticated` means the key file is already closed. `Finished` means
/// `ssh` exited.
pub enum SshPoll {
    Pending,
    NeedsTerminal,
    Authenticated,
    Finished(SshStatus),
}

pub struct SshProc {
    child: Child,
    pid: libc::pid_t,
    /// Read end of the stderr pipe. The reader thread owns the `File`.
    stderr_fd: RawFd,
    reader: Option<thread::JoinHandle<()>>,
    captured: Arc<Mutex<Vec<u8>>>,
    key_guard: KeyGuard,
    /// Keeps `/proc/<pid>/fd` visible to `ssh` until this session is dropped.
    _proc_access: ProcFdAccess,
    _config: File,
    /// Read end kept open so LocalCommand can open it through /proc.
    _ready_read: Option<File>,
    /// Closed to let ssh request the remote pty.
    ready_write: Option<File>,
    previous_group: Option<libc::pid_t>,
    reaped: bool,
    exit: Option<std::process::ExitStatus>,
}

impl SshProc {
    /// `leave_screen` asks the authentication signal to leave the alternate
    /// screen. The CLI passes false.
    pub fn spawn(mut session: Session, extra: &[String], leave_screen: bool) -> Result<Self> {
        let key_file = memfd(c"hdnfs-key", &session.private_key)?;
        session.private_key.zeroize();
        let key_fd = key_file.into_raw_fd();
        let key_guard = KeyGuard::arm(key_fd)?;
        LEAVE_SCREEN.store(leave_screen, Ordering::SeqCst);
        let config_file = memfd(c"hdnfs-config", session.config.as_bytes())?;
        let (ready_read, ready_write) = if leave_screen {
            let (read, write) = ready_pipe()?;
            (Some(read), Some(write))
        } else {
            (None, None)
        };
        let ready_fd = ready_read.as_ref().map(|file| file.as_raw_fd());
        let argv = ssh_argv(
            key_fd,
            std::os::fd::AsRawFd::as_raw_fd(&config_file),
            ready_fd,
            extra,
        )?;
        // ssh opens the key, the config, and the ready pipe through
        // /proc/<pid>/fd. Those paths are unreadable while this process is
        // non-dumpable. The guard turns that back on for this session only.
        let proc_access = ProcFdAccess::allow()?;
        let (stderr_read, stderr_write) = stderr_pipe()?;
        let mut cmd = Command::new("ssh");
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::from(stderr_write))
            .env_remove("SSH_AUTH_SOCK")
            .args(&argv);
        unsafe {
            cmd.pre_exec(|| {
                // The TUI ignores the stop signals that a background write would
                // raise. ssh needs the defaults, or Ctrl-Z inside the session does
                // nothing and a background write cannot stop ssh either.
                libc::signal(libc::SIGTTOU, libc::SIG_DFL);
                libc::signal(libc::SIGTTIN, libc::SIG_DFL);
                libc::signal(libc::SIGTSTP, libc::SIG_DFL);
                let mut blocked = std::mem::zeroed::<libc::sigset_t>();
                libc::sigemptyset(&mut blocked);
                libc::sigaddset(&mut blocked, libc::SIGTTOU);
                libc::sigaddset(&mut blocked, libc::SIGTTIN);
                libc::sigaddset(&mut blocked, libc::SIGTSTP);
                libc::sigprocmask(libc::SIG_UNBLOCK, &blocked, std::ptr::null_mut());
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                LEAVE_SCREEN.store(false, Ordering::SeqCst);
                return Err(Error::Message(format!("failed to execute ssh: {err}")));
            }
        };
        let stderr_fd = stderr_read.as_raw_fd();
        let (reader, captured) = spawn_stderr_reader(stderr_read);
        let pid = child.id() as libc::pid_t;
        unsafe {
            libc::setpgid(pid, pid);
        }
        Ok(Self {
            child,
            pid,
            stderr_fd,
            reader: Some(reader),
            captured,
            key_guard,
            _proc_access: proc_access,
            _config: config_file,
            _ready_read: ready_read,
            ready_write,
            previous_group: None,
            reaped: false,
            exit: None,
        })
    }

    pub fn poll(&mut self) -> Result<SshPoll> {
        if self.reaped {
            return Ok(SshPoll::Finished(self.wait_done()?));
        }
        // waitpid rejects WNOWAIT on Linux, which would reap a host-key stop
        // before ssh could be continued. waitid can look without reaping.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                &mut info,
                libc::WNOHANG | libc::WNOWAIT | libc::WEXITED | libc::WSTOPPED,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(self.pending_or_authed());
            }
            if err.raw_os_error() == Some(libc::ECHILD) {
                return Ok(SshPoll::Finished(self.wait_done()?));
            }
            return Err(Error::Message(format!("failed to wait for ssh: {err}")));
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(self.pending_or_authed());
        }
        match info.si_code {
            libc::CLD_STOPPED | libc::CLD_TRAPPED => Ok(self.stopped_poll()),
            libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED => {
                Ok(SshPoll::Finished(self.wait_done()?))
            }
            _ => Ok(self.pending_or_authed()),
        }
    }

    /// Hand `ssh` to a waiter without killing it.
    ///
    /// `Drop` would signal the child. Forgetting this value leaves the process
    /// running, and the stderr pipe stays open across `exec` so a later write
    /// cannot raise `SIGPIPE`.
    pub fn detach(mut self) -> (libc::pid_t, RawFd) {
        let pid = self.pid;
        let stderr_fd = self.stderr_fd;
        // LocalCommand is blocked in `cat` on the read end. Closing the write
        // end lets ssh continue, and it must happen after the terminal is cooked.
        self.ready_write.take();
        unsafe {
            libc::fcntl(stderr_fd, libc::F_SETFD, 0);
        }
        std::mem::forget(self);
        (pid, stderr_fd)
    }

    /// Put `ssh` in the foreground and continue it if a prompt stopped it.
    pub fn take_terminal(&mut self) {
        unsafe {
            libc::kill(-self.pid, libc::SIGCONT);
            libc::kill(self.pid, libc::SIGCONT);
        }
        if !io::stdin().is_terminal() {
            return;
        }
        let previous = unsafe { libc::getpgrp() };
        set_foreground_group(self.pid);
        self.previous_group = Some(previous);
    }

    pub fn wait_done(&mut self) -> Result<SshStatus> {
        if !self.reaped {
            let status = self
                .child
                .wait()
                .map_err(|err| Error::Message(format!("failed to wait for ssh: {err}")))?;
            self.exit = Some(status);
            self.reaped = true;
        }
        self.restore_group();
        self.join_reader();
        let status = self.exit;
        Ok(SshStatus {
            code: status.and_then(|status| status.code()),
            signal: status.and_then(|status| status.signal()),
            stderr: self.stderr_text(),
        })
    }

    pub fn cancel(&mut self) -> Result<()> {
        if self.reaped {
            self.join_reader();
            return Ok(());
        }
        self.signal(libc::SIGCONT);
        self.signal(libc::SIGTERM);
        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.exit = Some(status);
                    self.reaped = true;
                    self.restore_group();
                    self.join_reader();
                    return Ok(());
                }
                Ok(None) if started.elapsed() < Duration::from_millis(400) => {
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    self.signal(libc::SIGKILL);
                    if let Ok(status) = self.child.wait() {
                        self.exit = Some(status);
                    }
                    self.reaped = true;
                    self.restore_group();
                    self.join_reader();
                    return Ok(());
                }
                Err(err) => {
                    return Err(Error::Message(format!("failed to wait for ssh: {err}")));
                }
            }
        }
    }

    fn pending_or_authed(&self) -> SshPoll {
        if session_authed() {
            SshPoll::Authenticated
        } else {
            SshPoll::Pending
        }
    }

    fn stopped_poll(&self) -> SshPoll {
        if session_authed() {
            SshPoll::Authenticated
        } else {
            SshPoll::NeedsTerminal
        }
    }

    fn signal(&self, signal: libc::c_int) {
        unsafe {
            libc::kill(-self.pid, signal);
            libc::kill(self.pid, signal);
        }
    }

    fn restore_group(&mut self) {
        if let Some(previous) = self.previous_group.take() {
            set_foreground_group(previous);
        }
    }

    fn join_reader(&mut self) {
        let Some(reader) = self.reader.take() else {
            return;
        };
        // A grandchild can keep ssh's stderr open. Restoring the terminal must
        // not wait forever for that pipe to close.
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = reader.join();
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(Duration::from_millis(200));
    }

    fn stderr_text(&self) -> String {
        let bytes = self.captured.lock().unwrap_or_else(|err| err.into_inner());
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl Drop for SshProc {
    fn drop(&mut self) {
        LEAVE_SCREEN.store(false, Ordering::SeqCst);
        if !self.reaped {
            self.signal(libc::SIGCONT);
            self.signal(libc::SIGKILL);
            let _ = self.child.wait();
            self.reaped = true;
        }
        self.restore_group();
        self.join_reader();
        let _ = &self.key_guard;
    }
}

impl SshStatus {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    pub fn status_number(&self) -> u8 {
        if let Some(code) = self.code {
            return u8::try_from(code).unwrap_or(255);
        }
        let signal = self.signal.unwrap_or(9);
        let combined = 128u32.saturating_add(signal.max(0) as u32);
        u8::try_from(combined).unwrap_or(255)
    }

    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.status_number())
    }

    /// Text for the TUI after `ssh` returns. A clean session stays quiet.
    /// A zero status still reports a line that starts with `ssh:`, because
    /// that is OpenSSH's own diagnostic and the alternate screen would hide it.
    pub fn failure_note(&self) -> Option<String> {
        let diagnostic = self.stderr.lines().any(|line| line.starts_with("ssh:"));
        if self.success() && !diagnostic {
            return None;
        }
        Some(format_ssh_failure(self.code, &self.stderr))
    }
}

pub fn format_ssh_failure(code: Option<i32>, stderr: &str) -> String {
    let head = match code {
        Some(code) => format!("ssh exited with status {code}"),
        None => "ssh was killed by a signal".to_string(),
    };
    let detail = stderr.trim();
    if detail.is_empty() {
        head
    } else {
        format!("{head}\n{detail}")
    }
}

fn ready_pipe() -> Result<(File, File)> {
    stderr_pipe()
}

fn stderr_pipe() -> Result<(File, File)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(Error::Message(format!(
            "pipe failed: {}",
            io::Error::last_os_error()
        )));
    }
    unsafe {
        libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok((unsafe { File::from_raw_fd(fds[0]) }, unsafe {
        File::from_raw_fd(fds[1])
    }))
}

fn spawn_stderr_reader(read: File) -> (thread::JoinHandle<()>, Arc<Mutex<Vec<u8>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::clone(&captured);
    let handle = thread::spawn(move || {
        unsafe {
            let mut set = std::mem::zeroed::<libc::sigset_t>();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTSTP);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
        let mut read = read;
        let mut chunk = [0u8; 1024];
        loop {
            match read.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let mut buf = store.lock().unwrap_or_else(|err| err.into_inner());
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > 8192 {
                        let extra = buf.len() - 8192;
                        buf.drain(..extra);
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });
    (handle, captured)
}

fn memfd(name: &std::ffi::CStr, bytes: &[u8]) -> Result<File> {
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(Error::Message(format!(
            "memfd_create failed: {}",
            io::Error::last_os_error()
        )));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::fchmod(fd, 0o600) } != 0 {
        return Err(Error::Message(format!(
            "fchmod on memfd failed: {}",
            io::Error::last_os_error()
        )));
    }
    file.write_all(bytes)
        .map_err(|err| Error::Message(format!("failed to write memory file: {err}")))?;
    Ok(file)
}

fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(Error::Message(format!(
            "failed to disable core dumps: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

static KEY_FD: AtomicI32 = AtomicI32::new(-1);
static AUTHED: AtomicBool = AtomicBool::new(false);

pub(crate) fn session_authed() -> bool {
    AUTHED.load(Ordering::SeqCst)
}
/// The TUI sets this so authentication can leave the alternate screen before
/// the event loop next draws. The CLI leaves it false.
static LEAVE_SCREEN: AtomicBool = AtomicBool::new(false);

extern "C" fn close_key_fd(_sig: libc::c_int) {
    AUTHED.store(true, Ordering::SeqCst);
    let fd = KEY_FD.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
    if LEAVE_SCREEN.swap(false, Ordering::SeqCst) {
        const LEAVE: &[u8] =
            b"\x1b[?1049l\x1b[0m\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l";
        unsafe {
            libc::write(
                libc::STDOUT_FILENO,
                LEAVE.as_ptr() as *const libc::c_void,
                LEAVE.len(),
            );
        }
    }
}

struct ProcFdAccess;

impl ProcFdAccess {
    fn allow() -> Result<Self> {
        allow_proc_fd_access().map_err(|err| {
            Error::Message(format!("failed to expose session files to ssh: {err}"))
        })?;
        Ok(Self)
    }
}

impl Drop for ProcFdAccess {
    fn drop(&mut self) {
        restore_proc_privacy();
    }
}

struct KeyGuard;

impl KeyGuard {
    fn arm(fd: RawFd) -> Result<Self> {
        AUTHED.store(false, Ordering::SeqCst);
        KEY_FD.store(fd, Ordering::SeqCst);
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = close_key_fd as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        if unsafe { libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) } != 0 {
            let _ = unsafe { libc::close(KEY_FD.swap(-1, Ordering::SeqCst)) };
            return Err(Error::Message(format!(
                "failed to install SIGUSR1 handler: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(Self)
    }
}

impl Drop for KeyGuard {
    fn drop(&mut self) {
        let fd = KEY_FD.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

/// Internal argv. `main` accepts this before any user command and waits for
/// the `ssh` it already started. The same process id keeps the shell's job
/// alive, so the shell does not take the terminal back.
pub(crate) const WAIT_ARG: &str = "--hdnfs-ssh-wait";

pub(crate) fn exec_session_waiter(
    pid: libc::pid_t,
    stderr_fd: RawFd,
    termios_hex: &str,
) -> io::Error {
    let mut cmd = Command::new("/proc/self/exe");
    cmd.arg(WAIT_ARG)
        .arg(pid.to_string())
        .arg(stderr_fd.to_string())
        .arg(termios_hex)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Other threads disappear with this image. ssh is a separate process and
    // is not signaled. Destructors do not run.
    cmd.exec()
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn decode_termios_hex(hex: &str) -> Option<libc::termios> {
    let size = std::mem::size_of::<libc::termios>();
    if hex.len() != size * 2 {
        return None;
    }
    let mut bytes = vec![0u8; size];
    let digits = hex.as_bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        let hi = hex_nibble(digits[index * 2])?;
        let lo = hex_nibble(digits[index * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut termios as *mut libc::termios as *mut u8,
            size,
        );
    }
    Some(termios)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Wait for an `ssh` this process started. A pid that is not our child fails
/// before the terminal or any other descriptor is touched.
pub(crate) fn wait_for_session(args: &[String]) -> ExitCode {
    let Some((pid, stderr_fd, termios)) = parse_wait_args(args) else {
        return ExitCode::FAILURE;
    };
    if !child_is_ours(pid) {
        return ExitCode::FAILURE;
    }
    let stderr = if fd_is_open(stderr_fd) {
        Some(stderr_fd)
    } else {
        None
    };
    let status = collect_session(pid, stderr, termios);
    if let Some(note) = status.failure_note() {
        eprintln!("{note}");
    }
    status.exit_code()
}

fn parse_wait_args(args: &[String]) -> Option<(libc::pid_t, RawFd, Option<libc::termios>)> {
    if args.len() != 3 {
        return None;
    }
    let pid: libc::pid_t = args[0].parse().ok()?;
    if pid <= 0 {
        return None;
    }
    let stderr_fd: RawFd = args[1].parse().ok()?;
    if stderr_fd < 0 {
        return None;
    }
    let termios = if args[2].is_empty() {
        None
    } else {
        decode_termios_hex(&args[2])
    };
    Some((pid, stderr_fd, termios))
}

fn child_is_ours(pid: libc::pid_t) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WNOHANG | libc::WNOWAIT | libc::WEXITED | libc::WSTOPPED,
        )
    };
    rc == 0
}

fn fd_is_open(fd: RawFd) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

pub(crate) fn collect_session(
    pid: libc::pid_t,
    stderr_fd: Option<RawFd>,
    termios: Option<libc::termios>,
) -> SshStatus {
    if termios.is_some() {
        // The TUI's stop handler must not run inside the waiter. `exec` already
        // resets caught signals; the in-process fallback still has the handler.
        unsafe {
            libc::signal(libc::SIGTSTP, libc::SIG_DFL);
        }
    }
    if let Some(fd) = stderr_fd {
        set_nonblocking(fd, true);
    }
    let mut captured = Vec::new();
    let status = loop {
        if let Some(fd) = stderr_fd {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut pfd, 1, 200);
            }
            drain_stderr(fd, &mut captured);
        }
        let mut raw = 0;
        let flags = if stderr_fd.is_some() {
            libc::WNOHANG | libc::WUNTRACED
        } else {
            libc::WUNTRACED
        };
        let rc = unsafe { libc::waitpid(pid, &mut raw, flags) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break SshStatus {
                code: None,
                signal: Some(9),
                stderr: stderr_text(&captured),
            };
        }
        if rc == 0 {
            continue;
        }
        if libc::WIFSTOPPED(raw) {
            if termios.is_some() && io::stdin().is_terminal() {
                hand_session_back(pid, termios.as_ref());
            } else {
                unsafe {
                    libc::kill(-pid, libc::SIGCONT);
                    libc::kill(pid, libc::SIGCONT);
                }
            }
            continue;
        }
        if let Some(fd) = stderr_fd {
            drain_stderr(fd, &mut captured);
        }
        break status_from_wait(raw, stderr_text(&captured));
    };
    if let Some(fd) = stderr_fd {
        unsafe {
            libc::close(fd);
        }
    }
    if let Some(termios) = termios.as_ref() {
        restore_owned_termios(termios);
    }
    status
}

fn status_from_wait(raw: libc::c_int, stderr: String) -> SshStatus {
    if libc::WIFEXITED(raw) {
        SshStatus {
            code: Some(libc::WEXITSTATUS(raw)),
            signal: None,
            stderr,
        }
    } else if libc::WIFSIGNALED(raw) {
        SshStatus {
            code: None,
            signal: Some(libc::WTERMSIG(raw)),
            stderr,
        }
    } else {
        SshStatus {
            code: None,
            signal: Some(9),
            stderr,
        }
    }
}

fn hand_session_back(pid: libc::pid_t, termios: Option<&libc::termios>) {
    // ssh is stopped. Put the cooked mode back and stop this process so the
    // shell sees the job stop. `fg` continues us; we then continue ssh.
    if let Some(termios) = termios {
        restore_owned_termios(termios);
    }
    unsafe {
        libc::signal(libc::SIGTSTP, libc::SIG_DFL);
        let mut unblock = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut unblock);
        libc::sigaddset(&mut unblock, libc::SIGTSTP);
        libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
        libc::raise(libc::SIGTSTP);
        libc::kill(-pid, libc::SIGCONT);
        libc::kill(pid, libc::SIGCONT);
    }
    if io::stdin().is_terminal() {
        set_foreground_group(pid);
    }
}

fn restore_owned_termios(termios: &libc::termios) {
    if !io::stdin().is_terminal() {
        return;
    }
    let group = unsafe { libc::getpgrp() };
    set_foreground_group(group);
    unsafe {
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, termios);
    }
}

fn drain_stderr(fd: RawFd, captured: &mut Vec<u8>) {
    let mut chunk = [0u8; 1024];
    loop {
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
        if n > 0 {
            push_tail(captured, &chunk[..n as usize]);
            continue;
        }
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
        }
        break;
    }
}

fn push_tail(buf: &mut Vec<u8>, chunk: &[u8]) {
    buf.extend_from_slice(chunk);
    if buf.len() > 8192 {
        let extra = buf.len() - 8192;
        buf.drain(..extra);
    }
}

fn stderr_text(buf: &[u8]) -> String {
    String::from_utf8_lossy(buf).into_owned()
}

fn set_nonblocking(fd: RawFd, on: bool) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return;
        }
        let next = if on {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        libc::fcntl(fd, libc::F_SETFL, next);
    }
}

pub(crate) fn set_fd_blocking(fd: RawFd) {
    set_nonblocking(fd, false);
}

/// `tcsetpgrp` from a background process group raises `SIGTTOU`. The default
/// action stops the caller, which leaves a full-screen UI stuck on its last frame.
pub(crate) fn set_foreground_group(pgrp: libc::pid_t) {
    unsafe {
        // Ignored, and blocked for the call. A background tcsetpgrp otherwise
        // stops the process and the TUI never draws again.
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        let mut blocked = std::mem::zeroed::<libc::sigset_t>();
        let mut previous = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGTTOU);
        libc::sigaddset(&mut blocked, libc::SIGTTIN);
        libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut previous);
        libc::tcsetpgrp(libc::STDIN_FILENO, pgrp);
        libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdnfs::{init_volume, InitOptions, KdfParams};

    #[test]
    fn waiter_reaps_the_child_status_and_its_error_text() {
        use std::os::fd::FromRawFd;
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = fds[0];
        let write_fd = fds[1];
        let child = std::process::Command::new("sh")
            .arg("-c")
            .arg("echo 'ssh: broken' >&2; exit 42")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(unsafe { Stdio::from_raw_fd(write_fd) })
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        std::mem::forget(child);
        assert!(child_is_ours(pid));
        let status = collect_session(pid, Some(read_fd), None);
        assert_eq!(status.code, Some(42));
        let note = status.failure_note().unwrap();
        assert!(note.contains("status 42"), "{note}");
        assert!(note.contains("broken"), "{note}");
    }

    #[test]
    fn closing_the_ready_pipe_unblocks_the_reader() {
        let (read, write) = ready_pipe().unwrap();
        let path = format!("/proc/{}/fd/{}", std::process::id(), read.as_raw_fd());
        let mut child = std::process::Command::new("cat")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(child.try_wait().unwrap().is_none(), "cat should be waiting");
        drop(write);
        let status = child.wait().unwrap();
        assert!(status.success());
        drop(read);
    }

    #[test]
    fn waiter_rejects_a_pid_that_is_not_ours() {
        let code = wait_for_session(&["1".into(), "0".into(), String::new()]);
        assert_eq!(code, ExitCode::FAILURE);
    }

    #[test]
    fn termios_hex_roundtrips() {
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        termios.c_lflag = 0x1234;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &termios as *const libc::termios as *const u8,
                std::mem::size_of::<libc::termios>(),
            )
        };
        let hex = encode_hex(bytes);
        let back = decode_termios_hex(&hex).unwrap();
        assert_eq!(back.c_lflag, 0x1234);
        assert!(decode_termios_hex("").is_none());
        assert!(decode_termios_hex("zz").is_none());
    }

    #[test]
    fn a_noticed_exit_can_still_be_reaped() {
        // poll() uses waitid with WNOWAIT so a stopped ssh stays waitable.
        // Child::wait must still be able to reap that same exit.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as libc::id_t;
        let started = std::time::Instant::now();
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    &mut info,
                    libc::WNOHANG | libc::WNOWAIT | libc::WEXITED | libc::WSTOPPED,
                )
            };
            assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
            let noticed = unsafe { info.si_pid() } != 0
                && matches!(
                    info.si_code,
                    libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
                );
            if noticed {
                let waited = child.wait().unwrap();
                assert_eq!(waited.code(), Some(0));
                return;
            }
            if started.elapsed() > std::time::Duration::from_secs(2) {
                panic!("true did not exit");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn a_failed_ssh_note_keeps_the_diagnostic() {
        let failed = SshStatus {
            code: Some(255),
            signal: None,
            stderr: "ssh: Could not resolve hostname bad: Name or service not known\n".into(),
        };
        let note = failed.failure_note().unwrap();
        assert!(note.contains("status 255"), "{note}");
        assert!(note.contains("Could not resolve hostname"), "{note}");

        let quiet = SshStatus {
            code: Some(0),
            signal: None,
            stderr: String::new(),
        };
        assert!(quiet.failure_note().is_none());

        let hidden = SshStatus {
            code: Some(0),
            signal: None,
            stderr: "ssh: connect to host bad port 22: Connection refused\n".into(),
        };
        let note = hidden.failure_note().unwrap();
        assert!(note.contains("status 0"), "{note}");
        assert!(note.contains("Connection refused"), "{note}");
    }

    #[test]
    fn tags_hostnames_and_options_follow_the_rules() {
        validate_tag("laptop").unwrap();
        validate_tag("a.b_c-1").unwrap();
        assert!(validate_tag("").is_err());
        assert!(validate_tag("-nope").is_err());
        assert!(validate_tag("has space").is_err());
        validate_option_line("ProxyJump bastion").unwrap();
        validate_option_line("LocalForward 8080 localhost:8080").unwrap();
        assert!(validate_option_line("IdentityFile /tmp/key").is_err());
        assert!(validate_option_line("include other").is_err());
        assert!(validate_option_line("Host *").is_err());
        assert!(validate_option_line("ConnectTimeout 5").is_err());
        assert_eq!(parse_timeout("15").unwrap(), 15);
        assert!(parse_timeout("0").is_err());
        assert!(parse_timeout("3601").is_err());
        assert!(reject_extra(&["-L".into(), "8080:localhost:8080".into()]).is_ok());
        assert!(reject_extra(&["-i".into(), "/tmp/key".into()]).is_err());
        assert!(reject_extra(&["-o".into(), "IdentityFile=/tmp/key".into()]).is_err());
        let input = parse_host_args(&[
            "prod".into(),
            "--key".into(),
            "laptop".into(),
            "--hostname".into(),
            "203.0.113.10".into(),
            "--user".into(),
            "root".into(),
            "--port".into(),
            "22".into(),
            "--timeout".into(),
            "15".into(),
            "--option".into(),
            "ProxyJump bastion".into(),
        ])
        .unwrap();
        assert_eq!(input.tag, "prod");
        assert_eq!(input.port, Some(22));
        assert_eq!(input.timeout, Some(15));
        let updated = parse_host_args(&[
            "prod".into(),
            "--hostname=203.0.113.11".into(),
            "--key=laptop".into(),
        ])
        .unwrap();
        assert!(updated.user.is_none());
        assert!(updated.timeout.is_none());
        assert!(updated.options.is_empty());
        let host = HostRecord {
            key: "laptop".into(),
            hostname: "203.0.113.10".into(),
            user: Some("root".into()),
            port: Some(22),
            timeout: Some(15),
            options: vec!["ProxyJump bastion".into()],
        };
        let config = render_config(&host);
        let host_at = config.find("HostName").unwrap();
        let timeout_at = config.find("ConnectTimeout 15").unwrap();
        let proxy_at = config.find("ProxyJump").unwrap();
        assert!(host_at < timeout_at && timeout_at < proxy_at);
        assert!(config.starts_with("Host hdnfs\n"));
        assert_eq!(target_of(&host), "root@203.0.113.10:22");
        let connect_args = [
            "prod".into(),
            "--".into(),
            "-L".into(),
            "8080:localhost:8080".into(),
        ];
        let (tag, extra) = parse_connect(&connect_args).unwrap();
        assert_eq!(tag, "prod");
        let argv = ssh_argv(3, 4, None, &extra).unwrap();
        let local = argv
            .iter()
            .find(|arg| arg.starts_with("LocalCommand="))
            .unwrap();
        assert_eq!(
            local,
            &format!("LocalCommand=kill -USR1 {}", std::process::id())
        );
        let held = ssh_argv(3, 4, Some(9), &extra).unwrap();
        let held_local = held
            .iter()
            .find(|arg| arg.starts_with("LocalCommand="))
            .unwrap();
        assert!(
            held_local.contains(&format!("/proc/{}/fd/9", std::process::id())),
            "{held_local}"
        );
        let ident = argv.iter().position(|arg| arg == "-i").unwrap();
        let forward = argv.iter().position(|arg| arg == "-L").unwrap();
        let dest = argv.iter().position(|arg| arg == "hdnfs").unwrap();
        assert!(ident < forward && forward < dest);
        assert!(parse_connect(&["prod".into(), "-L".into()]).is_err());
    }

    #[test]
    fn generated_passwords_use_the_requested_alphabet() {
        let plain = generate_password(32, false).unwrap();
        let fancy = generate_password(64, true).unwrap();
        assert_eq!(plain.chars().count(), 32);
        assert_eq!(fancy.chars().count(), 64);
        assert!(plain.chars().all(|ch| ch.is_ascii_alphanumeric()));
        let symbols = "!@#$%^&*()-_=+";
        assert!(fancy
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || symbols.contains(ch)));
        assert_ne!(
            generate_password(32, false).unwrap().as_str(),
            generate_password(32, false).unwrap().as_str()
        );
        assert!(parse_password_length("7").is_err());
        assert!(parse_password_length("129").is_err());
        assert_eq!(parse_password_length(" 12 ").unwrap(), 12);
        assert!(parse_yes_no("yes").unwrap());
        assert!(!parse_yes_no("N").unwrap());
        assert!(parse_yes_no("maybe").is_err());
        assert!(validate_stored_password("").is_err());
        assert!(validate_stored_password("has\nnewline").is_err());
        assert!(validate_stored_password(&"x".repeat(1025)).is_err());
        validate_stored_password("correct horse battery").unwrap();
    }

    #[test]
    fn keys_and_hosts_roundtrip_and_the_root_lists_dot_drive() {
        let path = temp_volume("ssh");
        init_volume(InitOptions {
            path: &path.0,
            password: "correct horse battery",
            // Replacing a host copies that file and every parent before the old blocks are freed.
            size: Some(192 * 1024 * 1024),
            force: false,
            kdf: KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            progress: None,
        })
        .unwrap();
        let mut volume =
            Volume::open(&path.0, "correct horse battery", LockMode::Exclusive).unwrap();
        let created = create_key(&mut volume, "laptop", None).unwrap();
        assert!(created.line.starts_with("ssh-ed25519 "));
        assert!(created.line.contains("hdnfs:laptop"));
        assert_eq!(created.algorithm, "ed25519");
        let names: Vec<_> = volume
            .list("/")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert!(names.iter().any(|name| name == ".drive"));
        let rows = list_keys(&mut volume).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(format_key_row(&rows[0]).contains("ed25519"));
        let info = key_info(&mut volume, "laptop").unwrap();
        assert!(info.contains(&created.line));
        let exported = path.0.with_extension("pub");
        write_public_key(&mut volume, "laptop", &exported).unwrap();
        let written = std::fs::read_to_string(&exported).unwrap();
        assert_eq!(written, format!("{}\n", created.line));
        assert!(!written.contains("PRIVATE KEY"));
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&exported).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode, 0o644);
        let again = write_public_key(&mut volume, "laptop", &exported).unwrap_err();
        assert!(again.to_string().contains("already exists"), "{again}");
        assert_eq!(std::fs::read_to_string(&exported).unwrap(), written);
        let _ = std::fs::remove_file(&exported);
        let saved = path.0.with_extension("saved");
        std::fs::create_dir(&saved).unwrap();
        let got = export_key(&mut volume, "laptop", &saved).unwrap();
        assert_eq!(got.private_path, saved.join("laptop"));
        assert_eq!(got.public_path.as_ref(), Some(&saved.join("laptop.pub")));
        let private_bytes = std::fs::read(&got.private_path).unwrap();
        let stored_private = volume.read_bytes(&private_path("laptop")).unwrap();
        assert_eq!(private_bytes, stored_private.as_slice());
        assert_eq!(
            std::fs::read_to_string(got.public_path.as_ref().unwrap()).unwrap(),
            format!("{}\n", created.line)
        );
        let mode_of = |path: &std::path::Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode_of(&got.private_path), 0o600);
        assert_eq!(mode_of(got.public_path.as_ref().unwrap()), 0o644);
        let again = export_key(&mut volume, "laptop", &saved).unwrap_err();
        assert!(again.to_string().contains("already exists"), "{again}");
        assert_eq!(std::fs::read(&got.private_path).unwrap(), private_bytes);
        let missing = saved.join("no-such");
        let err = export_key(&mut volume, "laptop", &missing).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
        let _ = std::fs::remove_dir_all(&saved);
        let file = temp_key_path();
        let generated =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let pem = generated.to_openssh(ssh_key::LineEnding::LF).unwrap();
        std::fs::write(&file, pem.as_bytes()).unwrap();
        let added = add_key(&mut volume, "imported", &file)
            .unwrap()
            .expect("imported key has a public line");
        let stored = volume.read_bytes(&private_path("imported")).unwrap();
        assert_eq!(stored.as_slice(), pem.as_bytes());
        assert_eq!(
            added.line,
            generated.public_key().to_openssh().unwrap().trim()
        );
        create_host(
            &mut volume,
            &HostInput {
                tag: "prod".into(),
                key: "laptop".into(),
                hostname: "203.0.113.10".into(),
                user: Some("root".into()),
                port: Some(22),
                timeout: Some(15),
                options: vec!["ProxyJump bastion".into()],
            },
        )
        .unwrap();
        let blocked = add_password(&mut volume, "laptop", "correct horse battery").unwrap_err();
        assert!(blocked.to_string().contains("key"), "{blocked}");
        let blocked = add_password(&mut volume, "prod", "correct horse battery").unwrap_err();
        assert!(blocked.to_string().contains("host"), "{blocked}");
        add_password(&mut volume, "mail", "correct horse battery").unwrap();
        let rows = list_passwords(&mut volume).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(format_password_row(&rows[0]), "mail  21");
        assert!(!format_password_row(&rows[0]).contains("horse"));
        copy_password(&mut volume, "mail").unwrap();
        assert_eq!(take_copied().as_deref(), Some("correct horse battery"));
        let blocked = create_key(&mut volume, "mail", None).unwrap_err();
        assert!(blocked.to_string().contains("password"), "{blocked}");
        let blocked = create_host(
            &mut volume,
            &HostInput {
                tag: "mail".into(),
                key: "laptop".into(),
                hostname: "203.0.113.10".into(),
                user: None,
                port: None,
                timeout: None,
                options: Vec::new(),
            },
        )
        .unwrap_err();
        assert!(blocked.to_string().contains("password"), "{blocked}");
        generate_password_record(&mut volume, "site", 20, false).unwrap();
        let generated_secret = take_copied().unwrap();
        assert_eq!(generated_secret.chars().count(), 20);
        assert!(generated_secret
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric()));
        let stored = volume.read_bytes(&password_path("site")).unwrap();
        let stored = String::from_utf8(stored.to_vec()).unwrap();
        assert!(stored.contains(&generated_secret));
        let listed = list_passwords(&mut volume).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(!format_password_row(&listed[0]).contains(&generated_secret));
        assert!(!format_password_row(&listed[1]).contains(&generated_secret));
        delete_password(&mut volume, "mail").unwrap();
        delete_password(&mut volume, "site").unwrap();
        assert!(list_passwords(&mut volume).unwrap().is_empty());
        assert!(delete_key(&mut volume, "laptop").is_err());
        let listed = list_hosts(&mut volume).unwrap();
        assert_eq!(
            format_host_row(&listed[0]),
            "prod  root@203.0.113.10:22  laptop"
        );
        update_host(
            &mut volume,
            &HostInput {
                tag: "prod".into(),
                key: "imported".into(),
                hostname: "203.0.113.11".into(),
                user: None,
                port: None,
                timeout: None,
                options: Vec::new(),
            },
        )
        .unwrap();
        let host = load_host(&mut volume, "prod").unwrap();
        assert_eq!(host.key, "imported");
        assert!(host.user.is_none());
        assert!(host.timeout.is_none());
        assert!(host.options.is_empty());
        let session = load_session(&mut volume, "prod").unwrap();
        assert!(session.config.contains("HostName 203.0.113.11"));
        assert!(!session.config.contains("ConnectTimeout"));
        assert_eq!(session.private_key.as_slice(), pem.as_bytes());
        delete_host(&mut volume, "prod").unwrap();
        delete_key(&mut volume, "laptop").unwrap();
        delete_key(&mut volume, "imported").unwrap();
        assert!(list_keys(&mut volume).unwrap().is_empty());
        assert!(list_hosts(&mut volume).unwrap().is_empty());
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn test_data_keys_can_be_added() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-data");
        let path = temp_volume("ssh-add");
        init_volume(InitOptions {
            path: &path.0,
            password: "correct horse battery",
            size: Some(192 * 1024 * 1024),
            force: false,
            kdf: KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            progress: None,
        })
        .unwrap();
        let mut volume =
            Volume::open(&path.0, "correct horse battery", LockMode::Exclusive).unwrap();
        let cases = [
            (
                "meow",
                "ecdsa-sha2-nistp256",
                "SHA256:p6SIsW8NM9Oc4ww4AHszJ66kcW7FPembBaEZMMJXvgg",
            ),
            (
                "meow2",
                "ed25519",
                "SHA256:zQ3npw3HkPOPnyU/j6lZFAAWLHNHLpz0AD+q141ZLmk",
            ),
        ];
        for (tag, algorithm, fingerprint) in cases {
            let file = root.join(tag);
            let original = std::fs::read(&file).unwrap();
            let added = add_key(&mut volume, tag, &file)
                .unwrap_or_else(|err| panic!("{tag} was not added: {err}"))
                .unwrap_or_else(|| panic!("{tag} has no public line"));
            let stored = volume.read_bytes(&private_path(tag)).unwrap();
            assert_eq!(stored.len(), original.len(), "{tag} length");
            assert!(
                stored.as_slice() == original.as_slice(),
                "{tag} private bytes were not stored unchanged"
            );
            let expected = std::fs::read_to_string(root.join(format!("{tag}.pub"))).unwrap();
            let expected = expected.trim_end_matches(['\n', '\r']);
            assert_eq!(added.line, expected);
            assert_eq!(added.algorithm, algorithm);
            assert_eq!(added.fingerprint, fingerprint);
            assert_eq!(added.comment, "sveinn@zkynet");
            let info = key_info(&mut volume, tag).unwrap();
            assert!(info.contains(expected), "{tag} info missing public line");
            assert!(info.contains(algorithm));
            if tag == "meow" {
                let dest = std::env::temp_dir().join(format!(
                    "hdnfs-meow-{}-{}.pub",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                write_public_key(&mut volume, tag, &dest).unwrap();
                let written = std::fs::read_to_string(&dest).unwrap();
                assert_eq!(written.trim_end_matches(['\n', '\r']), expected);
                assert!(written.ends_with('\n'));
                let _ = std::fs::remove_file(&dest);
            }
        }
        let rows = list_keys(&mut volume).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(format_key_row(&rows[0]).contains("ecdsa-sha2-nistp256"));
        assert!(format_key_row(&rows[1]).contains("ed25519"));

        let junk = temp_key_path();
        let junk_bytes = b"not a private key\n";
        std::fs::write(&junk, junk_bytes).unwrap();
        assert!(add_key(&mut volume, "nope", &junk).unwrap().is_none());
        let stored = volume.read_bytes(&private_path("nope")).unwrap();
        assert_eq!(stored.as_slice(), junk_bytes);
        let raw_dest = std::env::temp_dir().join(format!(
            "hdnfs-raw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let err = write_public_key(&mut volume, "nope", &raw_dest).unwrap_err();
        assert!(err.to_string().contains("did not yield"), "{err}");
        assert!(!raw_dest.exists());
        let nested = raw_dest.join("missing").join("k.pub");
        let err = write_public_key(&mut volume, "meow", &nested).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
        let meta = volume.read_bytes(&meta_path("nope")).unwrap();
        let meta = String::from_utf8(meta.to_vec()).unwrap();
        assert!(!meta.contains("public"), "{meta}");
        let raw_dir = std::env::temp_dir().join(format!(
            "hdnfs-rawdir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&raw_dir).unwrap();
        let exported = export_key(&mut volume, "nope", &raw_dir).unwrap();
        assert!(exported.public_path.is_none());
        assert_eq!(std::fs::read(&exported.private_path).unwrap(), junk_bytes);
        assert!(!raw_dir.join("nope.pub").exists());
        let not_dir = export_key(&mut volume, "nope", &junk).unwrap_err();
        assert!(not_dir.to_string().contains("not a directory"), "{not_dir}");
        let _ = std::fs::remove_dir_all(&raw_dir);
        let pub_file = root.join("meow.pub");
        let original = std::fs::read(&pub_file).unwrap();
        assert!(add_key(&mut volume, "pubonly", &pub_file)
            .unwrap()
            .is_none());
        let stored = volume.read_bytes(&private_path("pubonly")).unwrap();
        assert_eq!(stored.as_slice(), original.as_slice());
        let rows = list_keys(&mut volume).unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(format_key_row(row_named(&rows, "nope")), "nope");
        assert_eq!(format_key_row(row_named(&rows, "pubonly")), "pubonly");
        let info = key_info(&mut volume, "nope").unwrap();
        assert!(info.starts_with("tag: nope\n"), "{info}");
        assert!(!info.contains("algorithm:"));
        assert!(!info.contains("public:"));
        create_host(
            &mut volume,
            &HostInput {
                tag: "raw".into(),
                key: "nope".into(),
                hostname: "203.0.113.10".into(),
                user: None,
                port: None,
                timeout: None,
                options: Vec::new(),
            },
        )
        .unwrap();
        let session = load_session(&mut volume, "raw").unwrap();
        assert_eq!(session.private_key.as_slice(), junk_bytes);
        std::fs::write(&junk, b"").unwrap();
        let err = add_key(&mut volume, "empty", &junk).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
        assert_eq!(list_keys(&mut volume).unwrap().len(), 4);
        let _ = std::fs::remove_file(&junk);
    }

    #[test]
    fn short_ecdsa_scalar_keeps_algorithm_fingerprint_and_comment() {
        let mut generated =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        generated.set_comment("kept-comment");
        let expected_fp = generated
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        let pem = generated.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let damaged = damage_ed25519_scalar(pem.as_bytes());
        assert!(ssh_key::PrivateKey::from_openssh(pem.as_bytes()).is_ok());
        assert!(ssh_key::PrivateKey::from_openssh(&damaged).is_err());
        let info = public_line_from_private(&damaged).expect("public line from damaged ed25519");
        assert_eq!(info.algorithm, "ed25519");
        assert_eq!(info.fingerprint, expected_fp);
        assert_eq!(info.comment, "kept-comment");

        let p521 = synthetic_short_p521();
        assert!(
            ssh_key::PrivateKey::from_openssh(&p521).is_err(),
            "the short scalar must be the case ssh-key rejects"
        );
        let info = public_line_from_private(&p521).expect("public line from short p521");
        assert_eq!(info.algorithm, "ecdsa-sha2-nistp521");
        assert_eq!(info.comment, "info@zkynet");
        assert!(info.fingerprint.starts_with("SHA256:"));
        assert!(info.line.starts_with("ecdsa-sha2-nistp521 "));
        assert!(info.line.ends_with(" info@zkynet"));

        let path = temp_volume("ssh-short");
        init_volume(InitOptions {
            path: &path.0,
            password: "correct horse battery",
            size: Some(128 * 1024 * 1024),
            force: false,
            kdf: KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            progress: None,
        })
        .unwrap();
        let mut volume =
            Volume::open(&path.0, "correct horse battery", LockMode::Exclusive).unwrap();
        let file = temp_key_path();
        std::fs::write(&file, &p521).unwrap();
        let added = add_key(&mut volume, "vtest", &file)
            .unwrap()
            .expect("short p521 has a public line");
        assert_eq!(added.algorithm, "ecdsa-sha2-nistp521");
        assert_eq!(added.comment, "info@zkynet");
        let stored = volume.read_bytes(&private_path("vtest")).unwrap();
        assert_eq!(stored.as_slice(), p521.as_slice());
        let row = format_key_row(row_named(&list_keys(&mut volume).unwrap(), "vtest"));
        assert!(row.contains("ecdsa-sha2-nistp521"), "{row}");
        assert!(row.contains(&added.fingerprint), "{row}");
        assert!(row.contains("info@zkynet"), "{row}");
        let info_text = key_info(&mut volume, "vtest").unwrap();
        assert!(
            info_text.contains("algorithm: ecdsa-sha2-nistp521"),
            "{info_text}"
        );
        assert!(info_text.contains(&added.fingerprint), "{info_text}");
        assert!(info_text.contains("comment: info@zkynet"), "{info_text}");

        // An add from before this parser stored the private file and left the public line out.
        let meta = br#"{"version":1}"#;
        volume.write_bytes(&meta_path("vtest"), meta).unwrap();
        let row = format_key_row(row_named(&list_keys(&mut volume).unwrap(), "vtest"));
        assert!(row.contains("ecdsa-sha2-nistp521"), "{row}");
        assert!(row.contains("info@zkynet"), "{row}");
        let info_text = key_info(&mut volume, "vtest").unwrap();
        assert!(info_text.contains("fingerprint:"), "{info_text}");
        assert!(info_text.contains("info@zkynet"), "{info_text}");
        let saved = path.0.with_extension("saved");
        std::fs::create_dir(&saved).unwrap();
        let got = export_key(&mut volume, "vtest", &saved).unwrap();
        let public = std::fs::read_to_string(got.public_path.as_ref().unwrap()).unwrap();
        assert!(public.starts_with("ecdsa-sha2-nistp521 "), "{public}");
        assert!(public.contains("info@zkynet"), "{public}");
        assert_eq!(std::fs::read(&got.private_path).unwrap(), p521);
        let _ = std::fs::remove_dir_all(&saved);
        let _ = std::fs::remove_file(&file);
    }

    /// Shorten the ed25519 private scalar so `PrivateKey::from_openssh` fails
    /// while the embedded public key and comment stay in place.
    fn damage_ed25519_scalar(pem: &[u8]) -> Vec<u8> {
        let raw = decode_openssh_container(pem).expect("pem");
        let mut raw = raw.to_vec();
        let mut off = OPENSSH_MAGIC.len();
        for _ in 0..3 {
            take_ssh_string(&raw, &mut off).unwrap();
        }
        take_u32(&raw, &mut off).unwrap();
        take_ssh_string(&raw, &mut off).unwrap();
        let private_len_at = off;
        let private_len = take_u32(&raw, &mut off).unwrap() as usize;
        let private_at = off;
        let mut inner_off = private_at + 8;
        take_ssh_string(&raw, &mut inner_off).unwrap();
        take_ssh_string(&raw, &mut inner_off).unwrap();
        let scalar_len_at = inner_off;
        let scalar_len = take_u32(&raw, &mut inner_off).unwrap() as usize;
        assert!(scalar_len > 8, "scalar {scalar_len}");
        let drop_n = scalar_len - 8;
        raw.drain(inner_off + 8..inner_off + scalar_len);
        raw[scalar_len_at..scalar_len_at + 4].copy_from_slice(&8u32.to_be_bytes());
        let new_private_len = (private_len - drop_n) as u32;
        raw[private_len_at..private_len_at + 4].copy_from_slice(&new_private_len.to_be_bytes());
        pem_wrap(&raw)
    }

    fn synthetic_short_p521() -> Vec<u8> {
        let point = {
            let mut point = vec![0x04];
            point.extend(std::iter::repeat(0x11u8).take(132));
            point
        };
        let mut public = Vec::new();
        push_ssh_string(&mut public, b"ecdsa-sha2-nistp521");
        push_ssh_string(&mut public, b"nistp521");
        push_ssh_string(&mut public, &point);
        let mut private = Vec::new();
        private.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        private.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        push_ssh_string(&mut private, b"ecdsa-sha2-nistp521");
        push_ssh_string(&mut private, b"nistp521");
        push_ssh_string(&mut private, &point);
        push_ssh_string(&mut private, &[0x22; 65]);
        push_ssh_string(&mut private, b"info@zkynet");
        let pad = (8 - private.len() % 8) % 8;
        if pad == 0 {
            private.extend(1..=8);
        } else {
            private.extend(1..=pad as u8);
        }
        let mut raw = Vec::new();
        raw.extend_from_slice(OPENSSH_MAGIC);
        push_ssh_string(&mut raw, b"none");
        push_ssh_string(&mut raw, b"none");
        push_ssh_string(&mut raw, b"");
        raw.extend_from_slice(&1u32.to_be_bytes());
        push_ssh_string(&mut raw, &public);
        push_ssh_string(&mut raw, &private);
        pem_wrap(&raw)
    }

    fn push_ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn pem_wrap(raw: &[u8]) -> Vec<u8> {
        const TAB: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut body = String::new();
        let mut i = 0;
        while i < raw.len() {
            let b0 = raw[i];
            let b1 = raw.get(i + 1).copied();
            let b2 = raw.get(i + 2).copied();
            let n = (u32::from(b0) << 16)
                | (u32::from(b1.unwrap_or(0)) << 8)
                | u32::from(b2.unwrap_or(0));
            body.push(TAB[((n >> 18) & 63) as usize] as char);
            body.push(TAB[((n >> 12) & 63) as usize] as char);
            body.push(match b1 {
                Some(_) => TAB[((n >> 6) & 63) as usize] as char,
                None => '=',
            });
            body.push(match b2 {
                Some(_) => TAB[(n & 63) as usize] as char,
                None => '=',
            });
            i += 3;
        }
        let mut out = b"-----BEGIN OPENSSH PRIVATE KEY-----\n".to_vec();
        for line in body.as_bytes().chunks(70) {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
        out.extend_from_slice(b"-----END OPENSSH PRIVATE KEY-----\n");
        out
    }

    struct Temp(std::path::PathBuf);

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn row_named<'a>(rows: &'a [KeyRow], tag: &str) -> &'a KeyRow {
        rows.iter()
            .find(|row| row.tag == tag)
            .unwrap_or_else(|| panic!("missing key {tag}"))
    }

    fn temp_volume(label: &str) -> Temp {
        let path = std::env::temp_dir().join(format!(
            "hdnfs-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Temp(path)
    }

    fn temp_key_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "hdnfs-key-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}
