use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, IsTerminal};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap,
};
use ratatui::{Frame, Terminal};
use zeroize::Zeroize;

use hdnfs::{
    block_device_bytes, format_unix_utc, has_volume_magic, init_volume, parse_size,
    validate_password, DirEntry, Error, InitOptions, KdfParams, Kind, LockMode, Result, Stat,
    Volume,
};

type Term = Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>;

pub fn run() -> Result<()> {
    if !io::stdout().is_terminal() {
        return Err(Error::Message("hdnfs ui needs a terminal".into()));
    }
    let mut terminal = ratatui::try_init().map_err(|err| Error::Message(err.to_string()))?;
    let mut app = App::new();
    let result = app.event_loop(&mut terminal);
    ratatui::restore();
    result
}

struct App {
    screen: Screen,
}

enum Screen {
    Pick(Pick),
    Sudo(Sudo),
    Unlock(Unlock),
    Setup(Setup),
    Browse(Browse),
}

struct Pick {
    disks: Vec<Disk>,
    selected: usize,
    editing: bool,
    path: String,
}

struct Disk {
    path: String,
    bytes: u64,
    model: String,
    removable: bool,
    partition: bool,
}

struct Sudo {
    path: PathBuf,
    password: Hidden,
}

struct Unlock {
    path: PathBuf,
    password: Hidden,
}

struct Setup {
    path: PathBuf,
    block: bool,
    fields: Vec<FieldId>,
    cursor: usize,
    capacity: Option<u64>,
    confirm: String,
    size: String,
    password: Hidden,
    again: Hidden,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldId {
    Confirm,
    Size,
    Password,
    Again,
}

struct Browse {
    volume_path: PathBuf,
    volume: Volume,
    cwd: String,
    entries: Vec<DirEntry>,
    selected: usize,
    marked: BTreeSet<String>,
    free: String,
    prompt: Prompt,
    notice_pending: Option<(bool, String)>,
    find: Option<VolumeFind>,
}

enum Prompt {
    None,
    Line { title: &'static str, value: String },
    Delete { path: String },
    Note { title: String, body: String },
    GetReview(GetReview),
    Host(HostBrowser),
}

struct GetReview {
    files: Vec<GetPick>,
    selected: usize,
    error: String,
}

#[derive(Clone)]
struct GetPick {
    src: String,
    name: String,
    size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HostJob {
    Put,
    Get,
}

struct HostBrowser {
    cwd: PathBuf,
    entries: Vec<HostEntry>,
    selected: usize,
    marked: BTreeSet<PathBuf>,
    error: String,
    progress: Option<HostProgress>,
    job: HostJob,
    getting: Vec<GetPick>,
    confirm: Option<PathBuf>,
    find: Option<HostFind>,
}

struct VolumeFind {
    anchor: String,
    query: String,
    needle: String,
    stem: String,
    cycling: bool,
}

struct HostFind {
    anchor: PathBuf,
    query: String,
    needle: String,
    stem: String,
    cycling: bool,
}

struct HostEntry {
    path: PathBuf,
    name: String,
    kind: HostKind,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostKind {
    Dir,
    File,
    Other,
}

struct HostProgress {
    current: String,
    done: u64,
    total: u64,
}

#[derive(Debug)]
enum PutOp {
    Mkdir(String),
    File { host: PathBuf, dest: String },
}

enum HostCmd {
    Stay,
    Close,
    Quit,
    Put,
    ConfirmGet,
    GetHere,
    Note(String),
}

enum GetPhase {
    Pending,
    Active,
    Done,
    Failed,
}

struct GetItem {
    name: String,
    src: String,
    dest: PathBuf,
    size: u64,
    written: u64,
    phase: GetPhase,
    error: String,
}

struct SetupPlan {
    path: PathBuf,
    size: Option<u64>,
    force: bool,
    password: Hidden,
}

struct Hidden(String);

impl Hidden {
    fn push(&mut self, ch: char) {
        if !ch.is_control() && self.0.len() < 1024 {
            self.0.push(ch);
        }
    }

    fn pop(&mut self) {
        self.0.pop();
    }

    fn expose(&self) -> &str {
        &self.0
    }

    fn clear(&mut self) {
        self.0.zeroize();
    }

    fn bullets(&self) -> String {
        "●".repeat(self.0.chars().count())
    }
}

impl Default for Hidden {
    fn default() -> Self {
        Self(String::new())
    }
}

impl Drop for Hidden {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl App {
    fn new() -> Self {
        let disks = list_disks();
        Self {
            screen: Screen::Pick(Pick {
                disks,
                selected: 0,
                editing: false,
                path: String::new(),
            }),
        }
    }

    fn event_loop(&mut self, terminal: &mut Term) -> Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;
            let event = event::read()?;
            if self.on_event(event, terminal)? {
                return Ok(());
            }
        }
    }

    fn note(&mut self, _bad: bool, _text: impl Into<String>) {}

    fn note_err(&mut self, _err: impl ToString) {}

    fn on_event(&mut self, event: Event, terminal: &mut Term) -> Result<bool> {
        let key = match event {
            Event::Key(key) if key.kind != KeyEventKind::Release => key,
            Event::Paste(text) => {
                self.paste(&text);
                return Ok(false);
            }
            _ => return Ok(false),
        };
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Ok(true);
        }
        match &mut self.screen {
            Screen::Pick(_) => self.on_pick(key),
            Screen::Sudo(_) => self.on_sudo(key),
            Screen::Unlock(_) => self.on_unlock(key),
            Screen::Setup(_) => self.on_setup(key, terminal),
            Screen::Browse(_) => self.on_browse(key, terminal),
        }
    }

    fn paste(&mut self, text: &str) {
        for ch in text.chars() {
            if ch == '\n' || ch == '\r' {
                break;
            }
            self.push_char(ch);
        }
    }

    fn push_char(&mut self, ch: char) {
        match &mut self.screen {
            Screen::Pick(pick) if pick.editing => push_limited(&mut pick.path, ch, 4096),
            Screen::Sudo(sudo) => sudo.password.push(ch),
            Screen::Unlock(unlock) => unlock.password.push(ch),
            Screen::Setup(setup) => setup.push(ch),
            Screen::Browse(browse) => browse.push(ch),
            Screen::Pick(_) => {}
        }
    }

    fn on_pick(&mut self, key: KeyEvent) -> Result<bool> {
        let editing = matches!(&self.screen, Screen::Pick(pick) if pick.editing);
        if editing {
            let entered = {
                let Screen::Pick(pick) = &mut self.screen else {
                    return Ok(false);
                };
                match key.code {
                    KeyCode::Esc => {
                        pick.editing = false;
                        pick.path.clear();
                        None
                    }
                    KeyCode::Backspace => {
                        pick.path.pop();
                        None
                    }
                    KeyCode::Enter => Some(PathBuf::from(pick.path.trim())),
                    KeyCode::Char(ch) => {
                        push_limited(&mut pick.path, ch, 4096);
                        None
                    }
                    _ => None,
                }
            };
            if let Some(path) = entered {
                if path.as_os_str().is_empty() {
                    self.note(true, "enter a path");
                } else {
                    self.begin_path(path);
                }
            }
            return Ok(false);
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Char('r') => {
                let disks = list_disks();
                if let Screen::Pick(pick) = &mut self.screen {
                    pick.selected = pick.selected.min(disks.len().saturating_sub(1));
                    pick.disks = disks;
                }
                self.note(false, "disk list refreshed");
            }
            KeyCode::Char('e') => {
                if let Screen::Pick(pick) = &mut self.screen {
                    pick.editing = true;
                    pick.path.clear();
                }
            }
            KeyCode::Char('/') => {
                if let Screen::Pick(pick) = &mut self.screen {
                    pick.editing = true;
                    pick.path = "/".to_string();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Screen::Pick(pick) = &mut self.screen {
                    let count = pick.disks.len();
                    if count > 0 {
                        pick.selected = (pick.selected + 1) % count;
                    }
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Screen::Pick(pick) = &mut self.screen {
                    let count = pick.disks.len();
                    if count > 0 {
                        pick.selected = (pick.selected + count - 1) % count;
                    }
                }
            }
            KeyCode::Enter => {
                let path = match &self.screen {
                    Screen::Pick(pick) => pick
                        .disks
                        .get(pick.selected)
                        .map(|disk| PathBuf::from(&disk.path)),
                    _ => None,
                };
                if let Some(path) = path {
                    self.begin_path(path);
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn begin_path(&mut self, path: PathBuf) {
        if !path.exists() {
            match Setup::create(path) {
                Ok(setup) => self.screen = Screen::Setup(setup),
                Err(err) => self.note_err(err),
            }
            return;
        }
        match super::sudo_password_needed(&path) {
            Ok(true) => {
                self.screen = Screen::Sudo(Sudo {
                    path,
                    password: Hidden::default(),
                });
            }
            Ok(false) => self.after_access(path),
            Err(err) => self.note_err(err),
        }
    }

    fn after_access(&mut self, path: PathBuf) {
        match has_volume_magic(&path) {
            Ok(true) => {
                self.screen = Screen::Unlock(Unlock {
                    path,
                    password: Hidden::default(),
                });
            }
            Ok(false) => match Setup::create(path) {
                Ok(setup) => self.screen = Screen::Setup(setup),
                Err(err) => self.note_err(err),
            },
            Err(err) => self.note_err(err),
        }
    }

    fn back_to_pick(&mut self) {
        let disks = list_disks();
        self.screen = Screen::Pick(Pick {
            disks,
            selected: 0,
            editing: false,
            path: String::new(),
        });
    }

    fn on_sudo(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Esc => self.back_to_pick(),
            KeyCode::Backspace => {
                if let Screen::Sudo(sudo) = &mut self.screen {
                    sudo.password.pop();
                }
            }
            KeyCode::Char(ch) => self.push_char(ch),
            KeyCode::Enter => {
                let (path, password) = {
                    let Screen::Sudo(sudo) = &mut self.screen else {
                        return Ok(false);
                    };
                    (
                        sudo.path.clone(),
                        Hidden(sudo.password.expose().to_string()),
                    )
                };
                match super::apply_sudo_password(&path, password.expose()) {
                    Ok(()) => self.after_access(path),
                    Err(err) => {
                        if let Screen::Sudo(sudo) = &mut self.screen {
                            sudo.password.clear();
                        }
                        self.note_err(err);
                    }
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn on_unlock(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Esc => self.back_to_pick(),
            KeyCode::Backspace => {
                if let Screen::Unlock(unlock) = &mut self.screen {
                    unlock.password.pop();
                }
            }
            KeyCode::Char(ch) => self.push_char(ch),
            KeyCode::Enter => self.try_unlock(),
            _ => {}
        }
        Ok(false)
    }

    fn try_unlock(&mut self) {
        let (path, password) = {
            let Screen::Unlock(unlock) = &mut self.screen else {
                return;
            };
            (
                unlock.path.clone(),
                Hidden(unlock.password.expose().to_string()),
            )
        };
        match validate_password(password.expose())
            .and_then(|_| Volume::open(&path, password.expose(), LockMode::Exclusive))
        {
            Ok(volume) => match Browse::open(path, volume) {
                Ok(browse) => {
                    self.screen = Screen::Browse(browse);
                    self.take_browse_notice();
                }
                Err(err) => self.note_err(err),
            },
            Err(err) => {
                if let Screen::Unlock(unlock) = &mut self.screen {
                    unlock.password.clear();
                }
                self.note_err(err);
            }
        }
    }

    fn on_setup(&mut self, key: KeyEvent, terminal: &mut Term) -> Result<bool> {
        match key.code {
            KeyCode::Esc => self.back_to_pick(),
            KeyCode::Tab | KeyCode::Down => {
                if let Screen::Setup(setup) = &mut self.screen {
                    if !setup.fields.is_empty() {
                        setup.cursor = (setup.cursor + 1) % setup.fields.len();
                    }
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                if let Screen::Setup(setup) = &mut self.screen {
                    if !setup.fields.is_empty() {
                        setup.cursor = (setup.cursor + setup.fields.len() - 1) % setup.fields.len();
                    }
                }
            }
            KeyCode::Backspace => {
                if let Screen::Setup(setup) = &mut self.screen {
                    setup.pop();
                }
            }
            KeyCode::Char(ch) => self.push_char(ch),
            KeyCode::Enter => self.submit_setup(terminal)?,
            _ => {}
        }
        Ok(false)
    }

    fn submit_setup(&mut self, terminal: &mut Term) -> Result<()> {
        let prepared = {
            let Screen::Setup(setup) = &mut self.screen else {
                return Ok(());
            };
            if setup.fields.contains(&FieldId::Confirm)
                && setup.confirm != setup.path.display().to_string()
            {
                Some(Err("confirmation did not match the volume path".to_string()))
            } else if setup.password.expose() != setup.again.expose() {
                Some(Err("passwords do not match".to_string()))
            } else if let Err(err) = validate_password(setup.password.expose()) {
                Some(Err(err.to_string()))
            } else {
                match chosen_size(setup) {
                    Ok(size) => Some(Ok(SetupPlan {
                        path: setup.path.clone(),
                        size,
                        force: setup.fields.contains(&FieldId::Confirm),
                        password: Hidden(setup.password.expose().to_string()),
                    })),
                    Err(err) => Some(Err(err)),
                }
            }
        };
        let Some(prepared) = prepared else {
            return Ok(());
        };
        let plan = match prepared {
            Ok(plan) => plan,
            Err(err) => {
                self.note(true, err);
                return Ok(());
            }
        };
        self.note(false, "");
        let label = plan.path.display().to_string();
        let mut on_progress = |stage: &str, done: u64, total: u64| {
            terminal.draw(|frame| draw_init_progress(frame, &label, stage, done, total))?;
            while event::poll(Duration::ZERO)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Release {
                        continue;
                    }
                    let cancel = key.code == KeyCode::Char('q')
                        || (key.modifiers.contains(KeyModifiers::CONTROL)
                            && key.code == KeyCode::Char('c'));
                    if cancel {
                        return Err(Error::Message("initialization canceled".into()));
                    }
                }
            }
            Ok(())
        };
        let initialized = init_volume(InitOptions {
            path: &plan.path,
            password: plan.password.expose(),
            size: plan.size,
            force: plan.force,
            kdf: KdfParams::default(),
            progress: Some(&mut on_progress),
        });
        match initialized {
            Ok(_) => match Volume::open(&plan.path, plan.password.expose(), LockMode::Exclusive) {
                Ok(volume) => match Browse::open(plan.path.clone(), volume) {
                    Ok(browse) => {
                        self.screen = Screen::Browse(browse);
                        self.take_browse_notice();
                    }
                    Err(err) => self.note_err(err),
                },
                Err(err) => self.note_err(err),
            },
            Err(err) => self.note_err(err),
        }
        Ok(())
    }

    fn on_browse(&mut self, key: KeyEvent, terminal: &mut Term) -> Result<bool> {
        let prompted = matches!(
            &self.screen,
            Screen::Browse(browse) if !matches!(browse.prompt, Prompt::None)
        );
        if prompted {
            return self.on_browse_prompt(key, terminal);
        }
        let finding = matches!(
            &self.screen,
            Screen::Browse(browse) if browse.find.is_some()
        );
        if finding {
            return self.on_volume_find(key);
        }
        let quit = {
            let Screen::Browse(browse) = &mut self.screen else {
                return Ok(false);
            };
            let count = browse.entries.len();
            match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    browse.notice_pending = Some((false, String::new()));
                    false
                }
                KeyCode::Down | KeyCode::Char('j') if count > 0 => {
                    browse.selected = (browse.selected + 1) % count;
                    false
                }
                KeyCode::Up | KeyCode::Char('k') if count > 0 => {
                    browse.selected = (browse.selected + count - 1) % count;
                    false
                }
                KeyCode::PageDown if count > 0 => {
                    browse.selected = (browse.selected + 10).min(count - 1);
                    false
                }
                KeyCode::PageUp => {
                    browse.selected = browse.selected.saturating_sub(10);
                    false
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    browse.open_dir();
                    false
                }
                KeyCode::Enter => false,
                KeyCode::Char(' ') if key.kind != KeyEventKind::Repeat => {
                    browse.toggle_mark();
                    false
                }
                KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('u') => {
                    browse.go_up();
                    false
                }
                KeyCode::Char('r') => {
                    browse.reload();
                    false
                }
                KeyCode::Char('n') => {
                    browse.prompt = Prompt::Line {
                        title: "directory name",
                        value: String::new(),
                    };
                    false
                }
                KeyCode::Char('p') => {
                    browse.prompt = Prompt::Host(HostBrowser::start());
                    false
                }
                KeyCode::Char('g') => {
                    browse.start_get();
                    false
                }
                KeyCode::Char('d') | KeyCode::Delete => {
                    browse.start_delete();
                    false
                }
                KeyCode::Char('i') => {
                    browse.show_selected_stat();
                    false
                }
                KeyCode::Char('v') => {
                    browse.show_volume_stat();
                    false
                }
                KeyCode::Char('?') => {
                    browse.prompt = Prompt::Note {
                        title: "keys".into(),
                        body: BROWSE_HELP.into(),
                    };
                    false
                }
                KeyCode::Char('/') => {
                    browse.begin_find();
                    false
                }
                _ => false,
            }
        };
        if quit {
            return Ok(true);
        }
        if matches!(key.code, KeyCode::Esc) {
            self.note(false, "");
            self.back_to_pick();
            return Ok(false);
        }
        self.take_browse_notice();
        Ok(false)
    }

    fn on_volume_find(&mut self, key: KeyEvent) -> Result<bool> {
        let Screen::Browse(browse) = &mut self.screen else {
            return Ok(false);
        };
        match key.code {
            KeyCode::Esc => browse.end_find(true),
            KeyCode::Enter => browse.end_find(false),
            KeyCode::Backspace => browse.find_pop(),
            KeyCode::BackTab => browse.complete_tab(-1),
            KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => browse.complete_tab(-1),
            KeyCode::Tab => browse.complete_tab(1),
            KeyCode::Char(ch) => browse.find_push(ch),
            KeyCode::Down | KeyCode::Right => browse.move_shown(1),
            KeyCode::Up | KeyCode::Left => browse.move_shown(-1),
            KeyCode::PageDown => browse.move_shown(10),
            KeyCode::PageUp => browse.move_shown(-10),
            _ => {}
        }
        self.take_browse_notice();
        Ok(false)
    }

    fn on_browse_prompt(&mut self, key: KeyEvent, terminal: &mut Term) -> Result<bool> {
        let host = matches!(
            &self.screen,
            Screen::Browse(browse) if matches!(browse.prompt, Prompt::Host(_))
        );
        if host {
            return self.on_host_key(key, terminal);
        }
        let Screen::Browse(browse) = &mut self.screen else {
            return Ok(false);
        };
        if matches!(browse.prompt, Prompt::GetReview(_)) {
            match key.code {
                KeyCode::Esc => browse.prompt = Prompt::None,
                KeyCode::Enter => {
                    let (files, duplicate) = match &browse.prompt {
                        Prompt::GetReview(review) => (
                            review.files.clone(),
                            duplicate_get_name(&review.files).map(str::to_string),
                        ),
                        _ => (Vec::new(), None),
                    };
                    if let Some(name) = duplicate {
                        if let Prompt::GetReview(review) = &mut browse.prompt {
                            review.error = format!("two files are named {name}");
                        }
                    } else if !files.is_empty() {
                        browse.prompt = Prompt::Host(HostBrowser::start_get(files));
                    }
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Right | KeyCode::Char('l') => {
                    if let Prompt::GetReview(review) = &mut browse.prompt {
                        review.move_cursor(1);
                    }
                }
                KeyCode::Up | KeyCode::Char('k') | KeyCode::Left | KeyCode::Char('h') => {
                    if let Prompt::GetReview(review) = &mut browse.prompt {
                        review.move_cursor(-1);
                    }
                }
                KeyCode::PageDown => {
                    if let Prompt::GetReview(review) = &mut browse.prompt {
                        review.move_cursor(10);
                    }
                }
                KeyCode::PageUp => {
                    if let Prompt::GetReview(review) = &mut browse.prompt {
                        review.move_cursor(-10);
                    }
                }
                KeyCode::Char('r') if key.kind != KeyEventKind::Repeat => {
                    if let Prompt::GetReview(review) = &mut browse.prompt {
                        review.remove_selected();
                    }
                }
                _ => {}
            }
            self.take_browse_notice();
            return Ok(false);
        }
        match &browse.prompt {
            Prompt::Note { .. } => {
                browse.prompt = Prompt::None;
            }
            Prompt::Delete { .. } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => browse.confirm_delete(),
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    browse.prompt = Prompt::None;
                }
                _ => {}
            },
            Prompt::Line { .. } => match key.code {
                KeyCode::Esc => browse.prompt = Prompt::None,
                KeyCode::Backspace => browse.pop(),
                KeyCode::Char(ch) => browse.push(ch),
                KeyCode::Enter => browse.submit_line(),
                _ => {}
            },
            Prompt::Host(_) | Prompt::None | Prompt::GetReview(_) => {}
        }
        self.take_browse_notice();
        Ok(false)
    }

    fn on_host_key(&mut self, key: KeyEvent, terminal: &mut Term) -> Result<bool> {
        let command = {
            let Screen::Browse(browse) = &mut self.screen else {
                return Ok(false);
            };
            let Prompt::Host(host) = &mut browse.prompt else {
                return Ok(false);
            };
            if host.confirm.is_some() {
                match key.code {
                    KeyCode::Enter => HostCmd::GetHere,
                    KeyCode::Esc => {
                        host.confirm = None;
                        HostCmd::Stay
                    }
                    _ => HostCmd::Stay,
                }
            } else if host.find.is_some() {
                match key.code {
                    KeyCode::Esc => {
                        host.end_find(true);
                        HostCmd::Stay
                    }
                    KeyCode::Enter => {
                        host.end_find(false);
                        HostCmd::Stay
                    }
                    KeyCode::Backspace => {
                        host.find_pop();
                        HostCmd::Stay
                    }
                    KeyCode::BackTab => {
                        host.complete_tab(-1);
                        HostCmd::Stay
                    }
                    KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
                        host.complete_tab(-1);
                        HostCmd::Stay
                    }
                    KeyCode::Tab => {
                        host.complete_tab(1);
                        HostCmd::Stay
                    }
                    KeyCode::Char(ch) => {
                        host.find_push(ch);
                        HostCmd::Stay
                    }
                    KeyCode::Down | KeyCode::Right => {
                        host.move_shown(1);
                        HostCmd::Stay
                    }
                    KeyCode::Up | KeyCode::Left => {
                        host.move_shown(-1);
                        HostCmd::Stay
                    }
                    KeyCode::PageDown => {
                        host.move_shown(10);
                        HostCmd::Stay
                    }
                    KeyCode::PageUp => {
                        host.move_shown(-10);
                        HostCmd::Stay
                    }
                    _ => HostCmd::Stay,
                }
            } else {
                match key.code {
                    KeyCode::Esc => HostCmd::Close,
                    KeyCode::Char('q') => HostCmd::Quit,
                    KeyCode::Down | KeyCode::Char('j') => {
                        host.move_cursor(1);
                        HostCmd::Stay
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        host.move_cursor(-1);
                        HostCmd::Stay
                    }
                    KeyCode::PageDown => {
                        host.move_cursor(10);
                        HostCmd::Stay
                    }
                    KeyCode::PageUp => {
                        host.move_cursor(-10);
                        HostCmd::Stay
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        host.open_selected();
                        HostCmd::Stay
                    }
                    KeyCode::Enter => match host.job {
                        HostJob::Put => HostCmd::Put,
                        HostJob::Get => HostCmd::ConfirmGet,
                    },
                    KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                        host.go_up();
                        HostCmd::Stay
                    }
                    KeyCode::Char(' ') if host.job == HostJob::Get => HostCmd::Stay,
                    KeyCode::Char(' ') if key.kind != KeyEventKind::Repeat => {
                        match host.toggle_selected() {
                            Ok(()) => HostCmd::Stay,
                            Err(err) => HostCmd::Note(err),
                        }
                    }
                    KeyCode::Char('r') => {
                        host.reload();
                        HostCmd::Stay
                    }
                    KeyCode::Char('~') => match user_home() {
                        Some(home) => {
                            host.jump(home);
                            HostCmd::Stay
                        }
                        None => HostCmd::Note("home directory is not available".into()),
                    },
                    KeyCode::Char('/') => {
                        host.begin_find();
                        HostCmd::Stay
                    }
                    _ => HostCmd::Stay,
                }
            }
        };
        match command {
            HostCmd::Stay => {}
            HostCmd::Close => self.close_host(),
            HostCmd::Quit => return Ok(true),
            HostCmd::Note(text) => self.note(true, text),
            HostCmd::Put => self.put_marked(terminal)?,
            HostCmd::ConfirmGet => self.ask_get_dest(),
            HostCmd::GetHere => self.begin_get(terminal)?,
        }
        self.take_browse_notice();
        Ok(false)
    }

    fn put_marked(&mut self, terminal: &mut Term) -> Result<()> {
        let prepared = {
            let Screen::Browse(browse) = &self.screen else {
                return Ok(());
            };
            let Prompt::Host(host) = &browse.prompt else {
                return Ok(());
            };
            let marked = if host.marked.is_empty() {
                match host.entries.get(host.selected) {
                    Some(entry) if entry.kind != HostKind::Other => Ok(vec![entry.path.clone()]),
                    Some(entry) => Err(format!("cannot select {}", entry.name)),
                    None => Ok(Vec::new()),
                }
            } else {
                Ok(host.marked.iter().cloned().collect())
            };
            marked.map(|paths| (browse.cwd.clone(), paths))
        };
        let (volume_cwd, marked) = match prepared {
            Ok(ready) => ready,
            Err(err) => {
                self.note(true, err);
                return Ok(());
            }
        };
        if marked.is_empty() {
            self.note(true, "nothing selected");
            return Ok(());
        }
        self.set_host_progress("Reading selection", 0, 1);
        terminal.draw(|frame| self.draw(frame))?;
        let plan = match plan_puts(&volume_cwd, &marked) {
            Ok(plan) => plan,
            Err(err) => {
                self.clear_host_progress();
                self.note(true, err);
                return Ok(());
            }
        };
        let skipped = plan.skipped;
        let ops = plan.ops;
        if ops.is_empty() {
            self.clear_host_progress();
            self.note(true, "nothing to store");
            return Ok(());
        }
        let total = ops.len() as u64;
        let started = {
            let Screen::Browse(browse) = &mut self.screen else {
                return Ok(());
            };
            browse.volume.begin_batch()
        };
        if let Err(err) = started {
            self.clear_host_progress();
            self.note(true, err.to_string());
            return Ok(());
        }
        let mut stop = CopyStop::Done;
        let mut io_error = None;
        for (index, op) in ops.iter().enumerate() {
            self.set_host_progress(op.label(), index as u64, total);
            if let Err(err) = terminal.draw(|frame| self.draw(frame)) {
                io_error = Some(Error::Io(err));
                break;
            }
            match put_stop() {
                Err(err) => {
                    io_error = Some(err);
                    break;
                }
                Ok(PutStop::Run) => {}
                Ok(PutStop::Cancel) => {
                    stop = CopyStop::Cancel(index as u64);
                    break;
                }
                Ok(PutStop::Close) => {
                    stop = CopyStop::Close(index as u64);
                    break;
                }
            }
            if let Err(err) = self.stage_copy(op) {
                stop = CopyStop::Failed(err.to_string());
                break;
            }
        }
        let committed = {
            let Screen::Browse(browse) = &mut self.screen else {
                return Ok(());
            };
            browse.volume.finish_batch()
        };
        self.clear_host_progress();
        let commit_error = committed.err().map(|err| err.to_string());
        self.note_copy_result(&stop, commit_error, &ops, &volume_cwd, &skipped);
        if let Some(err) = io_error {
            return Err(err);
        }
        Ok(())
    }

    fn stage_copy(&mut self, op: &PutOp) -> Result<()> {
        let Screen::Browse(browse) = &mut self.screen else {
            return Ok(());
        };
        match op {
            PutOp::Mkdir(path) => browse.volume.stage_mkdir(path),
            PutOp::File { host, dest } => {
                browse.volume.stage_put(host, dest)?;
                Ok(())
            }
        }
    }

    fn note_copy_result(
        &mut self,
        stop: &CopyStop,
        commit_error: Option<String>,
        ops: &[PutOp],
        volume_cwd: &str,
        skipped: &[PathBuf],
    ) {
        if matches!(stop, CopyStop::Close(_)) {
            self.close_host();
        }
        {
            let Screen::Browse(browse) = &mut self.screen else {
                return;
            };
            if commit_error.is_none() && matches!(stop, CopyStop::Done) {
                browse.prompt = Prompt::None;
            }
            browse.reload();
            if browse.notice_pending.is_some() {
                return;
            }
            if commit_error.is_none() && matches!(stop, CopyStop::Done) {
                let files = ops
                    .iter()
                    .filter(|op| matches!(op, PutOp::File { .. }))
                    .count();
                let dirs = ops.len() - files;
                browse.ok(put_notice(files, dirs, volume_cwd, skipped));
                return;
            }
        }
        if let Some(err) = commit_error {
            self.note(true, err);
            return;
        }
        match stop {
            CopyStop::Cancel(index) | CopyStop::Close(index) => {
                self.note(true, format!("put canceled after {index} of {}", ops.len()));
            }
            CopyStop::Failed(err) => self.note(true, err.clone()),
            CopyStop::Done => {}
        }
    }

    fn ask_get_dest(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        let Prompt::Host(host) = &mut browse.prompt else {
            return;
        };
        if host.job != HostJob::Get {
            return;
        }
        if !host.cwd.is_dir() {
            host.confirm = None;
            host.error = format!("{} is not a directory", host.cwd.display());
            return;
        }
        let dest = std::fs::canonicalize(&host.cwd).unwrap_or_else(|_| host.cwd.clone());
        host.confirm = Some(dest);
    }

    fn begin_get(&mut self, terminal: &mut Term) -> Result<()> {
        let prepared = {
            let Screen::Browse(browse) = &self.screen else {
                return Ok(());
            };
            let Prompt::Host(host) = &browse.prompt else {
                return Ok(());
            };
            if host.job != HostJob::Get {
                return Ok(());
            }
            let dest = host.confirm.clone().unwrap_or_else(|| host.cwd.clone());
            (dest, host.getting.clone())
        };
        let (dest_dir, files) = prepared;
        if !dest_dir.is_dir() {
            self.fail_host(format!("{} is not a directory", dest_dir.display()));
            return Ok(());
        }
        if files.is_empty() {
            self.fail_host("select a file".into());
            return Ok(());
        }
        self.run_get(terminal, dest_dir, files)
    }

    fn fail_host(&mut self, text: String) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        let Prompt::Host(host) = &mut browse.prompt else {
            return;
        };
        host.confirm = None;
        host.error = text;
    }

    fn run_get(
        &mut self,
        terminal: &mut Term,
        dest_dir: PathBuf,
        files: Vec<GetPick>,
    ) -> Result<()> {
        let mut items: Vec<GetItem> = files
            .into_iter()
            .map(|file| GetItem {
                dest: dest_dir.join(&file.name),
                name: file.name,
                src: file.src,
                size: file.size,
                written: 0,
                phase: GetPhase::Pending,
                error: String::new(),
            })
            .collect();
        let mut canceled = false;
        for index in 0..items.len() {
            if canceled {
                break;
            }
            items[index].phase = GetPhase::Active;
            items[index].written = 0;
            terminal.draw(|frame| draw_get_progress(frame, &items, &dest_dir, true))?;
            let src = items[index].src.clone();
            let dest = items[index].dest.clone();
            let mut terminal_error = None;
            let copied = {
                let Screen::Browse(browse) = &mut self.screen else {
                    return Ok(());
                };
                browse.volume.get_with(&src, &dest, &mut |written, total| {
                    items[index].written = written;
                    if total > 0 {
                        items[index].size = total;
                    }
                    if let Err(err) =
                        terminal.draw(|frame| draw_get_progress(frame, &items, &dest_dir, true))
                    {
                        terminal_error = Some(Error::Io(err));
                        return Err(Error::Message("terminal".into()));
                    }
                    match get_stop() {
                        Ok(true) => Err(Error::Message("get canceled".into())),
                        Ok(false) => Ok(()),
                        Err(err) => {
                            terminal_error = Some(err);
                            Err(Error::Message("terminal".into()))
                        }
                    }
                })
            };
            if let Some(err) = terminal_error {
                return Err(err);
            }
            match copied {
                Ok(_) => {
                    items[index].phase = GetPhase::Done;
                    items[index].written = items[index].size;
                }
                Err(Error::Message(text)) if text == "get canceled" => {
                    items[index].phase = GetPhase::Pending;
                    items[index].written = 0;
                    canceled = true;
                }
                Err(err) => {
                    items[index].phase = GetPhase::Failed;
                    items[index].error = err.to_string();
                }
            }
        }
        terminal.draw(|frame| draw_get_progress(frame, &items, &dest_dir, false))?;
        wait_get_close(terminal, &items, &dest_dir)?;
        let done = items
            .iter()
            .filter(|item| matches!(item.phase, GetPhase::Done))
            .count();
        let total = items.len();
        let failure = items
            .iter()
            .find(|item| matches!(item.phase, GetPhase::Failed));
        let Screen::Browse(browse) = &mut self.screen else {
            return Ok(());
        };
        for item in &items {
            if matches!(item.phase, GetPhase::Done) {
                browse.marked.remove(&item.src);
            }
        }
        browse.prompt = Prompt::None;
        if canceled {
            browse.fail_msg(format!("get canceled after {done} of {total}"));
        } else if let Some(failed) = failure {
            browse.fail_msg(format!("{}: {}", failed.name, failed.error));
        } else {
            let noun = if done == 1 { "file" } else { "files" };
            browse.ok(format!("got {done} {noun} into {}", dest_dir.display()));
        }
        Ok(())
    }

    fn set_host_progress(&mut self, current: impl Into<String>, done: u64, total: u64) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        let Prompt::Host(host) = &mut browse.prompt else {
            return;
        };
        host.progress = Some(HostProgress {
            current: current.into(),
            done,
            total,
        });
    }

    fn clear_host_progress(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        let Prompt::Host(host) = &mut browse.prompt else {
            return;
        };
        host.progress = None;
    }

    fn close_host(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        if let Prompt::Host(host) = &mut browse.prompt {
            host.marked.clear();
            host.progress = None;
        }
        browse.prompt = Prompt::None;
    }

    fn take_browse_notice(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.notice_pending.take();
    }

    fn draw(&self, frame: &mut Frame) {
        paint_screen(frame);
        let [header, body, help] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        paint_banner(frame, header, self.section(), &self.detail());
        match &self.screen {
            Screen::Pick(pick) => draw_pick(frame, body, pick),
            Screen::Sudo(sudo) => draw_secret(
                frame,
                body,
                "Grant access",
                &format!(
                    "sudo password to allow {} to open {}",
                    super::user_name(),
                    sudo.path.display()
                ),
                &sudo.password.bullets(),
            ),
            Screen::Unlock(unlock) => draw_secret(
                frame,
                body,
                "Unlock",
                &format!("{} is an HDNFS volume", unlock.path.display()),
                &unlock.password.bullets(),
            ),
            Screen::Setup(setup) => draw_setup(frame, body, setup),
            Screen::Browse(browse) => draw_browse(frame, body, browse),
        }
        frame.render_widget(Paragraph::new(self.help_line()).style(chrome(false)), help);
    }

    fn section(&self) -> &'static str {
        match &self.screen {
            Screen::Pick(_) => "Disks",
            Screen::Sudo(_) => "Access",
            Screen::Unlock(_) => "Unlock",
            Screen::Setup(_) => "Initialize",
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Host(host) if host.progress.is_some() => "Copy",
                Prompt::Host(host) if host.job == HostJob::Get => "Get",
                Prompt::Host(_) => "Put",
                Prompt::GetReview(_) => "Get",
                _ => "Volume",
            },
        }
    }

    fn detail(&self) -> String {
        match &self.screen {
            Screen::Pick(pick) => {
                let count = pick.disks.len();
                if count == 1 {
                    "1 disk".to_string()
                } else {
                    format!("{count} disks")
                }
            }
            Screen::Sudo(sudo) => sudo.path.display().to_string(),
            Screen::Unlock(unlock) => unlock.path.display().to_string(),
            Screen::Setup(setup) => setup.path.display().to_string(),
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Host(host) if host.job == HostJob::Get => host.cwd.display().to_string(),
                Prompt::Host(_) => format!("into {}", browse.cwd),
                Prompt::GetReview(_) => browse.cwd.clone(),
                _ => format!("{}   {}", browse.volume_path.display(), browse.cwd),
            },
        }
    }

    fn help_line(&self) -> Line<'static> {
        match &self.screen {
            Screen::Pick(pick) if pick.editing => keymap(&[("enter", "open"), ("esc", "cancel")]),
            Screen::Pick(_) => keymap(&[
                ("j k", "move"),
                ("enter", "open"),
                ("e", "path"),
                ("/", "path"),
                ("r", "refresh"),
                ("q", "quit"),
            ]),
            Screen::Sudo(_) | Screen::Unlock(_) => {
                keymap(&[("enter", "continue"), ("esc", "disks")])
            }
            Screen::Setup(_) => {
                keymap(&[("tab", "next"), ("enter", "initialize"), ("esc", "disks")])
            }
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Host(host) if host.progress.is_some() => {
                    keymap(&[("esc", "close"), ("q", "cancel")])
                }
                Prompt::Host(host) if host.confirm.is_some() => {
                    keymap(&[("enter", "move"), ("esc", "cancel")])
                }
                Prompt::Host(host) if host.find.is_some() => find_keymap(),
                Prompt::Host(host) if host.job == HostJob::Get => keymap(&[
                    ("h", "back"),
                    ("j k", "move"),
                    ("l", "open"),
                    ("/", "find"),
                    ("enter", "select"),
                    ("esc", "close"),
                    ("q", "quit"),
                ]),
                Prompt::Host(_) => keymap(&[
                    ("h", "back"),
                    ("j k", "move"),
                    ("l", "open"),
                    ("/", "find"),
                    ("space", "select"),
                    ("enter", "put"),
                    ("esc", "close"),
                    ("q", "quit"),
                ]),
                Prompt::GetReview(_) => keymap(&[
                    ("j k", "move"),
                    ("r", "remove"),
                    ("enter", "confirm"),
                    ("esc", "cancel"),
                ]),
                Prompt::None if browse.find.is_some() => find_keymap(),
                Prompt::None => keymap(&[
                    ("h", "back"),
                    ("j k", "move"),
                    ("l", "open"),
                    ("/", "find"),
                    ("space", "select"),
                    ("g", "get"),
                    ("p", "put"),
                    ("q", "quit"),
                ]),
                Prompt::Delete { .. } => keymap(&[("y", "delete"), ("n", "keep")]),
                Prompt::Note { .. } => keymap(&[("any key", "close")]),
                Prompt::Line { .. } => keymap(&[("enter", "confirm"), ("esc", "cancel")]),
            },
        }
    }
}

const INK: Color = Color::Rgb(14, 16, 22);
const RAISED: Color = Color::Rgb(24, 27, 36);
const LINE: Color = Color::Rgb(62, 70, 90);
const TEXT: Color = Color::Rgb(236, 238, 244);
const MUTED: Color = Color::Rgb(144, 152, 170);
const SAGE: Color = Color::Rgb(125, 201, 173);
const SAGE_INK: Color = Color::Rgb(12, 28, 24);
const BAD: Color = Color::Rgb(232, 140, 140);
const BAD_BG: Color = Color::Rgb(62, 28, 34);
const ACCENT: Color = SAGE;
const TRACK: Color = Color::Rgb(38, 46, 58);

fn fg(color: Color) -> Style {
    Style::default().fg(color)
}

fn surface() -> Style {
    fg(TEXT).bg(INK)
}

fn raised() -> Style {
    fg(TEXT).bg(RAISED)
}

fn chrome(bad: bool) -> Style {
    if bad {
        fg(BAD).bg(BAD_BG)
    } else {
        fg(MUTED).bg(RAISED)
    }
}

fn highlight() -> Style {
    fg(SAGE_INK).bg(SAGE)
}

fn bar_style(filled: bool) -> Style {
    if filled {
        fg(SAGE_INK).bg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        fg(MUTED).bg(TRACK)
    }
}

fn shell(title: impl Into<Line<'static>>, fill: Style) -> Block<'static> {
    let bg = fill.bg.unwrap_or(INK);
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(fg(LINE).bg(bg))
        .title_style(fg(MUTED).bg(bg))
        .title(title.into())
        .padding(Padding::horizontal(1))
        .style(fill)
}

fn panel(title: &str) -> Block<'static> {
    shell(format!(" {title} "), surface())
}

fn paint_screen(frame: &mut Frame) {
    frame.render_widget(Block::default().style(surface()), frame.area());
}

fn paint_banner(frame: &mut Frame, area: Rect, section: &str, detail: &str) {
    if area.is_empty() {
        return;
    }
    frame.render_widget(
        Paragraph::new(banner_line(area.width, section, detail)).style(raised()),
        area,
    );
}

fn banner_line(width: u16, section: &str, detail: &str) -> Line<'static> {
    let brand = Span::styled(" HDNFS", fg(SAGE).add_modifier(Modifier::BOLD));
    let section = Span::styled(format!("   {section}"), fg(TEXT));
    let left = brand.width() + section.width();
    let width = width as usize;
    let mut spans = vec![brand, section];
    if width > left {
        let budget = width - left;
        let fitted = fit(detail.trim(), budget.saturating_sub(1));
        let tail = if fitted.is_empty() {
            String::new()
        } else {
            format!("{fitted} ")
        };
        let tail_span = Span::styled(tail, fg(MUTED));
        let gap = budget.saturating_sub(tail_span.width());
        spans.push(Span::raw(" ".repeat(gap)));
        if tail_span.width() > 0 {
            spans.push(tail_span);
        }
    }
    Line::from(spans)
}

fn fit(text: &str, width: usize) -> String {
    if width == 0 || text.is_empty() {
        return String::new();
    }
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    let mut out: String = text.chars().take(width - 1).collect();
    out.push('…');
    out
}

fn find_keymap() -> Line<'static> {
    keymap(&[
        ("tab", "cycle"),
        ("esc", "cancel"),
        ("enter", "stay"),
        ("arrows", "move"),
    ])
}

fn keymap(pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (index, (key, label)) in pairs.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("    "));
        }
        spans.push(Span::styled((*key).to_string(), fg(SAGE)));
        spans.push(Span::styled(format!(" {label}"), fg(MUTED)));
    }
    Line::from(spans)
}

fn prompt_rect(area: Rect) -> Option<Rect> {
    let width = area.width.saturating_sub(4);
    if width == 0 || area.height < 3 {
        return None;
    }
    Some(Rect {
        x: area.x + 2,
        y: area.y + area.height - 2,
        width,
        height: 1,
    })
}

fn fill_line(frame: &mut Frame, area: Rect, line: Line<'_>, style: Style) {
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(line).style(style), area);
}

fn input_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {label} "), fg(SAGE)),
        Span::styled(value.to_string(), fg(TEXT)),
        Span::styled(" ", highlight()),
    ])
}

fn draw_pick(frame: &mut Frame, area: Rect, pick: &Pick) {
    if pick.disks.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "No disks found. Press e to type a path.",
                fg(MUTED),
            ))
            .block(panel("Devices"))
            .style(surface()),
            area,
        );
    } else {
        let items: Vec<ListItem> = pick
            .disks
            .iter()
            .map(|disk| ListItem::new(disk_row(disk)))
            .collect();
        let list = List::new(items)
            .block(panel("Devices"))
            .style(surface())
            .highlight_style(highlight());
        let mut state = ListState::default();
        if !pick.editing {
            state.select(Some(pick.selected));
        }
        frame.render_stateful_widget(list, area, &mut state);
    }
    if pick.editing {
        if let Some(rect) = prompt_rect(area) {
            fill_line(frame, rect, input_line("path", &pick.path), raised());
        }
    }
}

fn password_line(bullets: &str) -> Line<'static> {
    // A line that is only a normal space is placed on the following row.
    let cursor = if bullets.is_empty() { "\u{00a0}" } else { " " };
    Line::from(Span::styled(format!("{bullets}{cursor}"), highlight()))
}

fn draw_secret(frame: &mut Frame, area: Rect, title: &str, detail: &str, bullets: &str) {
    let area = dialog_area(area, 64, 7);
    let lines = vec![
        Line::from(Span::styled(detail.to_string(), fg(MUTED))),
        Line::from(""),
        Line::from(Span::styled("Password", fg(SAGE))),
        password_line(bullets),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(shell(format!(" {title} "), raised()))
            .style(raised())
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_setup(frame: &mut Frame, area: Rect, setup: &Setup) {
    let intro = if setup.block {
        "Retype the path to confirm. A smaller size uses a prefix and leaves the rest untouched."
    } else {
        "Choose a size, for example 64M. The password you set here unlocks the volume."
    };
    let mut lines = vec![
        Line::from(Span::styled(intro, fg(MUTED))),
        Line::from(""),
        labeled("Path", &setup.path.display().to_string()),
    ];
    if let Some(capacity) = setup.capacity {
        lines.push(labeled("Device", &human_bytes(capacity)));
    }
    lines.push(Line::from(""));
    for (index, field) in setup.fields.iter().enumerate() {
        lines.push(field_line(setup, index, *field));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel("New volume"))
            .style(surface())
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn labeled(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("   "),
        Span::styled(format!("{label:<14}"), fg(MUTED)),
        Span::styled(value.to_string(), fg(TEXT)),
    ])
}

fn field_line(setup: &Setup, index: usize, field: FieldId) -> Line<'static> {
    let active = index == setup.cursor;
    let marker = if active {
        Span::styled("▸  ", fg(SAGE).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("   ", fg(MUTED))
    };
    let label = format!("{:<14}", field.label(setup.block));
    let value = setup.value_of(field);
    let value_span = if active {
        Span::styled(format!("{value} "), highlight())
    } else {
        Span::styled(value, fg(TEXT))
    };
    Line::from(vec![
        marker,
        Span::styled(label, if active { fg(SAGE) } else { fg(MUTED) }),
        value_span,
    ])
}

fn draw_browse(frame: &mut Frame, area: Rect, browse: &Browse) {
    if let Prompt::GetReview(review) = &browse.prompt {
        draw_get_review(frame, area, review);
        return;
    }
    if let Prompt::Host(host) = &browse.prompt {
        if let Some(progress) = &host.progress {
            draw_put_progress(frame, area, &browse.cwd, progress);
        } else {
            draw_host(frame, area, &browse.cwd, host);
            if let Some(dest) = &host.confirm {
                draw_get_dest_dialog(frame, area, dest);
            }
        }
        return;
    }
    draw_entries(frame, area, browse);
    match &browse.prompt {
        Prompt::Note { title, body } => draw_note(frame, area, title, body),
        Prompt::Line { title, value } => {
            if let Some(rect) = prompt_rect(area) {
                fill_line(frame, rect, input_line(title, value), raised());
            }
        }
        Prompt::Delete { path } => {
            if let Some(rect) = prompt_rect(area) {
                fill_line(frame, rect, delete_line(path), fg(TEXT).bg(BAD_BG));
            }
        }
        Prompt::GetReview(_) | Prompt::Host(_) | Prompt::None => {}
    }
}

fn draw_entries(frame: &mut Frame, area: Rect, browse: &Browse) {
    let area = list_area(
        frame,
        area,
        browse.find.as_ref().map(|find| find.query.as_str()),
    );
    let block = volume_block(browse);
    let needle = browse
        .find
        .as_ref()
        .map(|find| find.needle.clone())
        .unwrap_or_default();
    if browse.entries.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("This directory is empty.", fg(MUTED)))
                .block(block)
                .style(surface()),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = browse
        .entries
        .iter()
        .filter(|entry| name_matches(&entry.name, &needle))
        .map(|entry| {
            let path = child_path(&browse.cwd, &entry.name);
            ListItem::new(entry_row(entry, browse.marked.contains(&path)))
        })
        .collect();
    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("No matches.", fg(MUTED)))
                .block(block)
                .style(surface()),
            area,
        );
        return;
    }
    let mut state = ListState::default();
    state.select(Some(browse.selected.min(items.len() - 1)));
    let list = List::new(items)
        .block(block)
        .style(surface())
        .highlight_style(highlight());
    frame.render_stateful_widget(list, area, &mut state);
}

fn delete_line(path: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(" Delete ", fg(BAD).add_modifier(Modifier::BOLD)),
        Span::styled(path.to_string(), fg(TEXT)),
        Span::styled("    y ", fg(TEXT).add_modifier(Modifier::BOLD)),
        Span::styled("delete", fg(BAD)),
        Span::styled("    n ", fg(TEXT).add_modifier(Modifier::BOLD)),
        Span::styled("keep", fg(TEXT)),
    ])
}

fn draw_note(frame: &mut Frame, area: Rect, title: &str, body: &str) {
    let lines = note_lines(body, title == "keys");
    let height = (lines.len() as u16).saturating_add(2).clamp(6, 24);
    let popup = dialog_area(area, 68, height);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(shell(format!(" {title} "), raised()))
            .style(raised())
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn note_lines(body: &str, keys: bool) -> Vec<Line<'static>> {
    let rows: Vec<&str> = body.lines().collect();
    let label_width = rows
        .iter()
        .filter_map(|line| {
            line.split_once(": ")
                .map(|(label, _)| label.chars().count())
        })
        .max()
        .unwrap_or(0);
    rows.into_iter()
        .map(|line| {
            if let Some((label, rest)) = line.split_once(": ") {
                let label_style = if keys { fg(SAGE) } else { fg(MUTED) };
                Line::from(vec![
                    Span::styled(format!("{label:<label_width$}  "), label_style),
                    Span::styled(rest.to_string(), fg(TEXT)),
                ])
            } else if line.is_empty() {
                Line::from("")
            } else {
                Line::from(Span::styled(line.to_string(), fg(TEXT)))
            }
        })
        .collect()
}

fn dialog_area(area: Rect, width: u16, height: u16) -> Rect {
    if area.width <= width.saturating_add(4) || area.height <= height.saturating_add(2) {
        return area;
    }
    centered(area, width, height)
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    ratatui::layout::Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

impl FieldId {
    fn label(self, _block: bool) -> &'static str {
        match self {
            FieldId::Confirm => "Confirm path",
            FieldId::Size => "Size",
            FieldId::Password => "Password",
            FieldId::Again => "Confirm",
        }
    }
}

fn chosen_size(setup: &Setup) -> std::result::Result<Option<u64>, String> {
    let text = setup.size.trim();
    if text.is_empty() {
        if setup.block {
            Ok(None)
        } else {
            Err("file volumes require a size".to_string())
        }
    } else {
        parse_size(text).map(Some).map_err(|err| err.to_string())
    }
}

impl Setup {
    fn create(path: PathBuf) -> Result<Self> {
        let block = super::is_block(&path);
        let needs_confirm = if block {
            true
        } else {
            match std::fs::metadata(&path) {
                Ok(meta) if meta.is_file() && meta.len() > 0 => true,
                Ok(meta) if meta.is_file() => false,
                Ok(_) => {
                    return Err(Error::Message(
                        "volume path is not a file or a block device".into(),
                    ));
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => false,
                Err(err) => return Err(err.into()),
            }
        };
        let capacity = if block {
            Some(block_device_bytes(&path)?)
        } else {
            None
        };
        let mut fields = Vec::new();
        if needs_confirm {
            fields.push(FieldId::Confirm);
        }
        fields.push(FieldId::Size);
        fields.push(FieldId::Password);
        fields.push(FieldId::Again);
        Ok(Self {
            path,
            block,
            fields,
            cursor: 0,
            capacity,
            confirm: String::new(),
            size: String::new(),
            password: Hidden::default(),
            again: Hidden::default(),
        })
    }

    fn active(&self) -> FieldId {
        self.fields
            .get(self.cursor)
            .copied()
            .unwrap_or(FieldId::Password)
    }

    fn push(&mut self, ch: char) {
        if ch.is_control() {
            return;
        }
        match self.active() {
            FieldId::Confirm => push_limited(&mut self.confirm, ch, 4096),
            FieldId::Size => push_limited(&mut self.size, ch, 64),
            FieldId::Password => self.password.push(ch),
            FieldId::Again => self.again.push(ch),
        }
    }

    fn pop(&mut self) {
        match self.active() {
            FieldId::Confirm => {
                self.confirm.pop();
            }
            FieldId::Size => {
                self.size.pop();
            }
            FieldId::Password => self.password.pop(),
            FieldId::Again => self.again.pop(),
        }
    }

    fn value_of(&self, field: FieldId) -> String {
        match field {
            FieldId::Confirm => self.confirm.clone(),
            FieldId::Size => self.size.clone(),
            FieldId::Password => self.password.bullets(),
            FieldId::Again => self.again.bullets(),
        }
    }
}

impl Browse {
    fn open(volume_path: PathBuf, volume: Volume) -> Result<Self> {
        let mut browse = Self {
            volume_path,
            volume,
            cwd: "/".to_string(),
            entries: Vec::new(),
            selected: 0,
            marked: BTreeSet::new(),
            free: String::new(),
            prompt: Prompt::None,
            notice_pending: None,
            find: None,
        };
        browse.reload();
        Ok(browse)
    }

    fn reload(&mut self) {
        match self.volume.list(&self.cwd) {
            Ok(entries) => {
                self.entries = entries;
                if self.selected >= self.entries.len() {
                    self.selected = self.entries.len().saturating_sub(1);
                }
            }
            Err(err) => self.fail(err),
        }
        match self.volume.stat(None) {
            Ok(Stat::Volume {
                free_blocks,
                free_payload_bytes,
                ..
            }) => {
                self.free = format!(
                    "free {free_blocks} blocks, {} payload",
                    human_bytes(free_payload_bytes)
                );
            }
            Ok(_) => {}
            Err(err) => self.fail(err),
        }
    }

    fn selected_entry(&self) -> Option<&DirEntry> {
        self.entries.get(self.selected)
    }

    fn open_dir(&mut self) {
        let Some(entry) = self.selected_entry().cloned() else {
            return;
        };
        if entry.kind != Kind::Dir {
            return;
        }
        self.cwd = child_path(&self.cwd, &entry.name);
        self.selected = 0;
        self.reload();
    }

    fn go_up(&mut self) {
        if self.cwd == "/" {
            return;
        }
        let leaving = self.cwd.rsplit('/').next().map(str::to_string);
        self.cwd = parent_path(&self.cwd);
        self.selected = 0;
        self.reload();
        let Some(name) = leaving else {
            return;
        };
        if let Some(index) = self.entries.iter().position(|entry| entry.name == name) {
            self.selected = index;
        }
    }

    fn toggle_mark(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.fail_msg("nothing to select");
            return;
        };
        if entry.kind != Kind::File {
            self.fail_msg("select a file");
            return;
        }
        let path = child_path(&self.cwd, &entry.name);
        if !self.marked.remove(&path) {
            self.marked.insert(path);
        }
    }

    fn start_get(&mut self) {
        let (files, error) = match self.files_for_get() {
            Ok(files) => {
                let error = duplicate_get_name(&files)
                    .map(|name| format!("two files are named {name}"))
                    .unwrap_or_default();
                (files, error)
            }
            Err(err) => (Vec::new(), err),
        };
        self.prompt = Prompt::GetReview(GetReview {
            files,
            selected: 0,
            error,
        });
    }

    fn files_for_get(&mut self) -> std::result::Result<Vec<GetPick>, String> {
        let paths = if self.marked.is_empty() {
            match self.selected_entry() {
                Some(entry) if entry.kind == Kind::File => {
                    vec![child_path(&self.cwd, &entry.name)]
                }
                _ => return Err("select a file".into()),
            }
        } else {
            self.marked.iter().cloned().collect()
        };
        let mut files = Vec::with_capacity(paths.len());
        for src in paths {
            match self.volume.stat(Some(&src)) {
                Ok(Stat::Node {
                    kind: Kind::File,
                    size,
                    path,
                    ..
                }) => {
                    let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                    files.push(GetPick {
                        src: path,
                        name,
                        size,
                    });
                }
                Ok(_) => return Err(format!("{src} is a directory")),
                Err(err) => return Err(err.to_string()),
            }
        }
        order_get_picks(&mut files);
        Ok(files)
    }

    fn start_delete(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.fail_msg("nothing selected");
            return;
        };
        let path = child_path(&self.cwd, &entry.name);
        self.prompt = Prompt::Delete { path };
    }

    fn show_selected_stat(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.show_volume_stat();
            return;
        };
        let path = child_path(&self.cwd, &entry.name);
        match self.volume.stat(Some(&path)) {
            Ok(stat) => {
                self.prompt = Prompt::Note {
                    title: "stat".into(),
                    body: format_stat(&stat),
                };
            }
            Err(err) => self.fail(err),
        }
    }

    fn show_volume_stat(&mut self) {
        match self.volume.stat(None) {
            Ok(stat) => {
                self.prompt = Prompt::Note {
                    title: "volume".into(),
                    body: format_stat(&stat),
                };
            }
            Err(err) => self.fail(err),
        }
    }

    fn confirm_delete(&mut self) {
        let Prompt::Delete { path } = &self.prompt else {
            return;
        };
        let path = path.clone();
        self.prompt = Prompt::None;
        match self.volume.delete(&path) {
            Ok(()) => {
                self.ok(format!("deleted {path}"));
                self.reload();
            }
            Err(err) => self.fail(err),
        }
    }

    fn submit_line(&mut self) {
        let Prompt::Line { value, .. } = &self.prompt else {
            return;
        };
        let value = value.trim().to_string();
        self.prompt = Prompt::None;
        if value.is_empty() {
            self.fail_msg("empty input");
            return;
        }
        let path = child_path(&self.cwd, &value);
        match self.volume.mkdir(&path) {
            Ok(()) => {
                self.ok(format!("created {path}"));
                self.reload();
            }
            Err(err) => self.fail(err),
        }
    }

    fn push(&mut self, ch: char) {
        if let Prompt::Line { value, .. } = &mut self.prompt {
            push_limited(value, ch, 4096);
            return;
        }
        if let Prompt::Host(host) = &mut self.prompt {
            if host.confirm.is_none() && host.progress.is_none() && host.find.is_some() {
                host.find_push(ch);
            }
            return;
        }
        if matches!(self.prompt, Prompt::None) && self.find.is_some() {
            self.find_push(ch);
        }
    }

    fn begin_find(&mut self) {
        if self.find.is_some() {
            return;
        }
        self.find = Some(VolumeFind {
            anchor: self.cwd.clone(),
            query: String::new(),
            needle: String::new(),
            stem: String::new(),
            cycling: false,
        });
    }

    fn find_push(&mut self, ch: char) {
        let Some(find) = &mut self.find else {
            return;
        };
        let before = find.query.len();
        push_limited(&mut find.query, ch, 4096);
        if find.query.len() == before {
            return;
        }
        self.apply_find();
    }

    fn find_pop(&mut self) {
        let Some(find) = &mut self.find else {
            return;
        };
        if find.query.pop().is_none() {
            return;
        }
        self.apply_find();
    }

    fn apply_find(&mut self) {
        let (anchor, query, old_needle) = {
            let Some(find) = &self.find else {
                return;
            };
            (find.anchor.clone(), find.query.clone(), find.needle.clone())
        };
        let (cwd, needle) = volume_follow(&mut self.volume, &anchor, &query);
        let cwd_changed = self.cwd != cwd;
        if cwd_changed {
            self.cwd = cwd;
            self.reload();
        }
        if cwd_changed || old_needle != needle {
            self.selected = 0;
        }
        if let Some(find) = &mut self.find {
            find.needle = needle;
            find.stem = query_stem(&query);
            find.cycling = false;
        }
    }

    fn end_find(&mut self, cancel: bool) {
        if self.find.is_none() {
            return;
        }
        let anchor = self
            .find
            .as_ref()
            .map(|find| find.anchor.clone())
            .unwrap_or_default();
        let kept = self.visible_selection_name();
        self.find = None;
        if cancel && self.cwd != anchor {
            self.cwd = anchor;
            self.reload();
            self.selected = 0;
            return;
        }
        self.select_name(kept);
    }

    fn complete_tab(&mut self, delta: isize) {
        let names = self.visible_names();
        let Some(find) = &self.find else {
            return;
        };
        let Some(cycled) = cycle_match(
            &names,
            self.selected,
            &find.stem,
            &find.query,
            find.cycling,
            delta,
        ) else {
            return;
        };
        self.selected = cycled.index;
        if let Some(find) = &mut self.find {
            find.query = cycled.query;
            find.cycling = true;
        }
    }

    fn move_shown(&mut self, delta: isize) {
        let count = self.visible_count();
        move_index(&mut self.selected, count, delta);
        if let Some(find) = &mut self.find {
            find.cycling = false;
        }
    }

    fn visible_names(&self) -> Vec<String> {
        let needle = self
            .find
            .as_ref()
            .map(|find| find.needle.clone())
            .unwrap_or_default();
        self.entries
            .iter()
            .filter(|entry| name_matches(&entry.name, &needle))
            .map(|entry| entry.name.clone())
            .collect()
    }

    fn visible_count(&self) -> usize {
        let needle = self
            .find
            .as_ref()
            .map(|find| find.needle.clone())
            .unwrap_or_default();
        self.entries
            .iter()
            .filter(|entry| name_matches(&entry.name, &needle))
            .count()
    }

    fn visible_selection_name(&self) -> Option<String> {
        let needle = self
            .find
            .as_ref()
            .map(|find| find.needle.clone())
            .unwrap_or_default();
        self.entries
            .iter()
            .filter(|entry| name_matches(&entry.name, &needle))
            .nth(self.selected)
            .map(|entry| entry.name.clone())
    }

    fn select_name(&mut self, name: Option<String>) {
        let Some(name) = name else {
            return;
        };
        if let Some(index) = self.entries.iter().position(|entry| entry.name == name) {
            self.selected = index;
        }
    }

    fn pop(&mut self) {
        if let Prompt::Line { value, .. } = &mut self.prompt {
            value.pop();
        }
    }

    fn ok(&mut self, text: impl Into<String>) {
        self.notice_pending = Some((false, text.into()));
    }

    fn fail(&mut self, err: Error) {
        self.notice_pending = Some((true, err.to_string()));
    }

    fn fail_msg(&mut self, text: impl Into<String>) {
        self.notice_pending = Some((true, text.into()));
    }
}

fn volume_block(browse: &Browse) -> Block<'static> {
    let title = if browse.cwd == "/" {
        "Root".to_string()
    } else {
        browse.cwd.clone()
    };
    let mut block = panel(&title);
    let count = browse.marked.len();
    if count > 0 {
        let noun = if count == 1 { "file" } else { "files" };
        block = block.title(
            Line::from(Span::styled(format!(" {count} {noun} selected "), fg(SAGE)))
                .right_aligned(),
        );
    }
    block
}

fn entry_row(entry: &DirEntry, marked: bool) -> Line<'static> {
    let (mark, mark_style) = match (entry.kind, marked) {
        (Kind::File, true) => ("●", fg(SAGE)),
        (Kind::File, false) => ("○", fg(MUTED)),
        (Kind::Dir, _) => (" ", fg(MUTED)),
    };
    match entry.kind {
        Kind::Dir => Line::from(vec![
            Span::styled(format!("{mark}  "), mark_style),
            Span::styled("dir   ", fg(SAGE)),
            Span::styled(format!("{:8}  ", ""), fg(MUTED)),
            Span::styled(entry.name.clone(), fg(TEXT)),
        ]),
        Kind::File => Line::from(vec![
            Span::styled(format!("{mark}  "), mark_style),
            Span::styled("file  ", fg(MUTED)),
            Span::styled(format!("{:>8}  ", human_bytes(entry.size)), fg(MUTED)),
            Span::styled(entry.name.clone(), fg(TEXT)),
        ]),
    }
}

fn format_stat(stat: &Stat) -> String {
    match stat {
        Stat::Volume {
            size,
            block_size,
            data_blocks,
            used_blocks,
            free_blocks,
            free_payload_bytes,
        } => format!(
            "type: volume\nsize: {size}\nblock_size: {block_size}\ndata_blocks: {data_blocks}\nused_blocks: {used_blocks}\nfree_blocks: {free_blocks}\nfree_payload_bytes: {free_payload_bytes}"
        ),
        Stat::Node {
            path,
            kind,
            size,
            created,
            modified,
        } => format!(
            "type: {}\npath: {path}\nsize: {size}\ncreated: {}\nmodified: {}",
            kind.as_str(),
            format_unix_utc(*created),
            format_unix_utc(*modified)
        ),
    }
}

const BROWSE_HELP: &str = "\
move: j or k, or the arrow keys
open: l or right opens a directory
up: h, left, or backspace
enter: does nothing here
select: space toggles a file
get: g opens a page of the selected files
on that page: j or k moves, r removes a file, enter confirms, esc cancels
then choose a directory. enter shows its full path, enter moves, esc cancels
new: n creates a directory here
put: p opens your home directory
in the put browser: h or left goes up, l or right opens a directory
select: space toggles the cursor there
copy: enter stores the selection there
close: esc drops that selection
delete: d or delete, then y or n
stat: i for the selection, v for the volume
find: / opens a path field here and in the file pickers
filter: typed text narrows the open directory
slash: / at the end of a name opens that directory
complete: tab cycles the filtered names, shift-tab goes backward
stay: enter keeps the directory you reached
cancel: esc returns to where you pressed /
refresh: r
disks: esc
quit: q
help: ?";

fn push_limited(text: &mut String, ch: char, max_bytes: usize) {
    if ch.is_control() {
        return;
    }
    if text.len() + ch.len_utf8() <= max_bytes {
        text.push(ch);
    }
}

fn child_path(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn parent_path(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => path[..index].to_string(),
    }
}

struct PathSteps {
    absolute: bool,
    enter: Vec<String>,
    needle: String,
}

fn path_steps(query: &str) -> PathSteps {
    let absolute = query.starts_with('/');
    let mut parts: Vec<String> = query.split('/').map(str::to_string).collect();
    if absolute && parts.first().is_some_and(|part| part.is_empty()) {
        parts.remove(0);
    }
    let trailing = parts.last().is_some_and(|part| part.is_empty());
    if trailing {
        parts.pop();
    }
    parts.retain(|part| !part.is_empty());
    if trailing || parts.is_empty() {
        PathSteps {
            absolute,
            enter: parts,
            needle: String::new(),
        }
    } else {
        let needle = parts.pop().unwrap_or_default();
        PathSteps {
            absolute,
            enter: parts,
            needle,
        }
    }
}

fn name_matches(name: &str, needle: &str) -> bool {
    needle.is_empty() || name.starts_with(needle)
}

fn query_stem(query: &str) -> String {
    if query.is_empty() || query.ends_with('/') {
        return query.to_string();
    }
    match query.rfind('/') {
        Some(index) => query[..=index].to_string(),
        None => String::new(),
    }
}

struct MatchCycle {
    index: usize,
    query: String,
}

fn cycle_match(
    names: &[String],
    selected: usize,
    stem: &str,
    query: &str,
    cycling: bool,
    delta: isize,
) -> Option<MatchCycle> {
    let count = names.len();
    if count == 0 || delta == 0 {
        return None;
    }
    let current = selected.min(count - 1);
    let filled = format!("{stem}{}", names[current]);
    let mut index = current;
    if cycling || query == filled || delta < 0 {
        move_index(&mut index, count, delta);
    }
    let next = format!("{stem}{}", names[index]);
    if next.len() > 4096 {
        return None;
    }
    Some(MatchCycle { index, query: next })
}

fn volume_follow(volume: &mut Volume, anchor: &str, query: &str) -> (String, String) {
    let steps = path_steps(query);
    let mut cwd = if steps.absolute {
        "/".to_string()
    } else {
        anchor.to_string()
    };
    for name in steps.enter {
        if name == "." || name.is_empty() {
            continue;
        }
        if name == ".." {
            cwd = parent_path(&cwd);
            continue;
        }
        let next = child_path(&cwd, &name);
        match volume.stat(Some(&next)) {
            Ok(Stat::Node {
                kind: Kind::Dir, ..
            }) => cwd = next,
            _ => return (cwd, name),
        }
    }
    (cwd, steps.needle)
}

fn follow_path(anchor: &Path, query: &str) -> (PathBuf, String) {
    let steps = path_steps(query);
    let mut cwd = if steps.absolute {
        PathBuf::from("/")
    } else {
        anchor.to_path_buf()
    };
    for name in steps.enter {
        if name == "." || name.is_empty() {
            continue;
        }
        if name == ".." {
            cwd = host_parent(&cwd);
            continue;
        }
        let next = cwd.join(&name);
        if next.is_dir() {
            cwd = next;
        } else {
            return (cwd, name);
        }
    }
    (cwd, steps.needle)
}

fn host_parent(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => {
            if path.is_absolute() {
                PathBuf::from("/")
            } else {
                path.to_path_buf()
            }
        }
    }
}

fn move_index(selected: &mut usize, count: usize, delta: isize) {
    if count == 0 {
        *selected = 0;
        return;
    }
    if delta == 1 || delta == -1 {
        let next = *selected as isize + delta;
        *selected = if next < 0 {
            count - 1
        } else if (next as usize) >= count {
            0
        } else {
            next as usize
        };
        return;
    }
    if delta > 0 {
        *selected = (*selected + delta as usize).min(count - 1);
    } else {
        *selected = selected.saturating_sub(delta.unsigned_abs());
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut unit = 0usize;
    let mut value = bytes;
    while value >= 1024 && unit < 4 {
        value /= 1024;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        let scaled = bytes as f64 / 1024_f64.powi(unit as i32);
        format!("{scaled:.1} {}", UNITS[unit])
    }
}

fn disk_row(disk: &Disk) -> Line<'static> {
    let kind = if disk.partition { "part" } else { "disk" };
    let kind_style = if disk.removable { fg(SAGE) } else { fg(MUTED) };
    let mut spans = vec![
        Span::styled(format!("{:<20}", disk.path), fg(TEXT)),
        Span::styled(format!("{:>8}   ", human_bytes(disk.bytes)), fg(MUTED)),
        Span::styled(format!("{kind:<4}   "), kind_style),
        Span::styled(disk.model.clone(), fg(MUTED)),
    ];
    if disk.removable {
        spans.push(Span::styled("   removable", fg(SAGE)));
    }
    Line::from(spans)
}

fn list_disks() -> Vec<Disk> {
    let mut disks = Vec::new();
    let Ok(blocks) = std::fs::read_dir("/sys/block") else {
        return disks;
    };
    for entry in blocks.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if ignored_disk(&name) {
            continue;
        }
        let removable = read_trimmed(&entry.path().join("removable")) == "1";
        let model = read_trimmed(&entry.path().join("device").join("model"));
        push_disk(&mut disks, &name, &entry.path(), false, removable, &model);
        let Ok(children) = std::fs::read_dir(entry.path()) else {
            continue;
        };
        for child in children.flatten() {
            let child_name = child.file_name().to_string_lossy().into_owned();
            if child_name.starts_with(&name) && child.path().join("size").is_file() {
                push_disk(
                    &mut disks,
                    &child_name,
                    &child.path(),
                    true,
                    removable,
                    &model,
                );
            }
        }
    }
    disks.sort_by(|left, right| {
        right
            .removable
            .cmp(&left.removable)
            .then(left.path.cmp(&right.path))
    });
    disks
}

fn push_disk(
    disks: &mut Vec<Disk>,
    name: &str,
    sys_path: &Path,
    partition: bool,
    removable: bool,
    model: &str,
) {
    let dev = PathBuf::from("/dev").join(name);
    if !dev.exists() {
        return;
    }
    let Some(sectors) = read_u64(&sys_path.join("size")) else {
        return;
    };
    disks.push(Disk {
        path: dev.display().to_string(),
        bytes: sectors.saturating_mul(512),
        model: model.trim().to_string(),
        removable,
        partition,
    });
}

fn ignored_disk(name: &str) -> bool {
    name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("fd")
        || name.starts_with("dm-")
        || name.starts_with("md")
        || name.starts_with("zram")
        || name.starts_with("nbd")
        || name.starts_with("sr")
}

fn read_trimmed(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .trim_matches('\0')
        .to_string()
}

fn read_u64(path: &Path) -> Option<u64> {
    read_trimmed(path).parse().ok()
}

fn stage_line(stage: &str) -> String {
    match stage {
        "writing" => "Writing free space".to_string(),
        "sealing" => "Sealing the volume".to_string(),
        other => other.to_string(),
    }
}

fn draw_init_progress(frame: &mut Frame, path: &str, stage: &str, done: u64, total: u64) {
    paint_screen(frame);
    let [header, body, help] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    paint_banner(frame, header, "Initialize", path);
    let ratio = if total == 0 {
        1.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    };
    draw_meter(
        frame,
        body,
        &stage_line(stage),
        path,
        stage_detail(stage),
        ratio,
        &format!("{done} / {total} MiB"),
    );
    frame.render_widget(
        Paragraph::new(keymap(&[("q", "cancel"), ("ctrl-c", "cancel")])).style(chrome(false)),
        help,
    );
}

fn stage_detail(stage: &str) -> &'static str {
    match stage {
        "writing" => "Free space is filled before the volume is sealed.",
        "sealing" => "The superblock is written and synced.",
        _ => "",
    }
}

fn draw_meter(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    primary: &str,
    secondary: &str,
    ratio: f64,
    meta: &str,
) {
    let area = dialog_area(area, 68, 10);
    let block = shell(format!(" {title} "), raised()).padding(Padding::horizontal(2));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.is_empty() {
        return;
    }
    let pct = (ratio * 100.0).round() as u16;
    let bar_height = if inner.height >= 8 { 3 } else { 1 };
    let [text, _, bar, meta_area, _] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(bar_height),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .areas(inner);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                primary.to_string(),
                fg(TEXT).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(secondary.to_string(), fg(MUTED))),
        ])
        .style(raised())
        .wrap(Wrap { trim: false }),
        text,
    );
    paint_bar(frame, bar, ratio, &format!("{pct}%"));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(meta.to_string(), fg(MUTED)))).style(raised()),
        meta_area,
    );
}

fn paint_bar(frame: &mut Frame, area: Rect, ratio: f64, label: &str) {
    if area.is_empty() {
        return;
    }
    let filled = ((f64::from(area.width) * ratio).round() as u16).min(area.width);
    let buf = frame.buffer_mut();
    for y in area.y..area.bottom() {
        for x in area.x..area.right() {
            buf[(x, y)]
                .set_symbol(" ")
                .set_style(bar_style(x - area.x < filled));
        }
    }
    let label_width = label.chars().count() as u16;
    if label_width == 0 || label_width > area.width {
        return;
    }
    let start = area.x + (area.width - label_width) / 2;
    let row = area.y + area.height / 2;
    for (index, ch) in label.chars().enumerate() {
        let x = start + index as u16;
        buf[(x, row)]
            .set_char(ch)
            .set_style(bar_style(x - area.x < filled));
    }
}

impl HostBrowser {
    fn start() -> Self {
        let cwd = user_home().unwrap_or_else(|| PathBuf::from("/"));
        let mut host = Self {
            cwd,
            entries: Vec::new(),
            selected: 0,
            marked: BTreeSet::new(),
            error: String::new(),
            progress: None,
            job: HostJob::Put,
            getting: Vec::new(),
            confirm: None,
            find: None,
        };
        host.reload();
        host
    }

    fn start_get(files: Vec<GetPick>) -> Self {
        let mut host = Self::start();
        host.job = HostJob::Get;
        host.getting = files;
        host
    }

    fn reload(&mut self) {
        match list_host_dir(&self.cwd) {
            Ok(entries) => {
                self.entries = entries;
                self.error.clear();
                if self.selected >= self.entries.len() {
                    self.selected = self.entries.len().saturating_sub(1);
                }
            }
            Err(err) => {
                self.entries.clear();
                self.selected = 0;
                self.error = err;
            }
        }
    }

    fn move_cursor(&mut self, delta: isize) {
        let count = self.entries.len();
        if count == 0 {
            self.selected = 0;
            return;
        }
        if delta == 1 || delta == -1 {
            let next = self.selected as isize + delta;
            self.selected = if next < 0 {
                count - 1
            } else if (next as usize) >= count {
                0
            } else {
                next as usize
            };
            return;
        }
        if delta > 0 {
            self.selected = (self.selected + delta as usize).min(count - 1);
        } else {
            self.selected = self.selected.saturating_sub(delta.unsigned_abs());
        }
    }

    fn open_selected(&mut self) {
        let Some(entry) = self.entries.get(self.selected) else {
            return;
        };
        if entry.kind != HostKind::Dir {
            return;
        }
        self.cwd = entry.path.clone();
        self.selected = 0;
        self.reload();
    }

    fn go_up(&mut self) {
        let Some(parent) = self.cwd.parent() else {
            return;
        };
        if parent.as_os_str().is_empty() {
            return;
        }
        let parent = parent.to_path_buf();
        let leaving = self.cwd.file_name().map(|name| name.to_os_string());
        self.cwd = parent;
        self.selected = 0;
        self.reload();
        if let Some(name) = leaving {
            if let Some(index) = self.entries.iter().position(|entry| {
                entry
                    .path
                    .file_name()
                    .is_some_and(|entry_name| entry_name == name)
            }) {
                self.selected = index;
            }
        }
    }

    fn jump(&mut self, path: PathBuf) {
        self.cwd = std::fs::canonicalize(&path).unwrap_or(path);
        self.selected = 0;
        self.reload();
    }

    fn toggle_selected(&mut self) -> std::result::Result<(), String> {
        let Some(entry) = self.entries.get(self.selected) else {
            return Err("nothing to select".into());
        };
        if entry.kind == HostKind::Other {
            return Err(format!("cannot select {}", entry.name));
        }
        let path = entry.path.clone();
        if !self.marked.remove(&path) {
            self.marked.insert(path);
        }
        Ok(())
    }

    fn begin_find(&mut self) {
        if self.progress.is_some() || self.confirm.is_some() || self.find.is_some() {
            return;
        }
        self.find = Some(HostFind {
            anchor: self.cwd.clone(),
            query: String::new(),
            needle: String::new(),
            stem: String::new(),
            cycling: false,
        });
    }

    fn find_push(&mut self, ch: char) {
        let Some(find) = &mut self.find else {
            return;
        };
        let before = find.query.len();
        push_limited(&mut find.query, ch, 4096);
        if find.query.len() == before {
            return;
        }
        self.apply_find();
    }

    fn find_pop(&mut self) {
        let Some(find) = &mut self.find else {
            return;
        };
        if find.query.pop().is_none() {
            return;
        }
        self.apply_find();
    }

    fn apply_find(&mut self) {
        let (anchor, query, old_needle) = {
            let Some(find) = &self.find else {
                return;
            };
            (find.anchor.clone(), find.query.clone(), find.needle.clone())
        };
        let (cwd, needle) = follow_path(&anchor, &query);
        let cwd_changed = self.cwd != cwd;
        if cwd_changed {
            self.cwd = cwd;
            self.reload();
        }
        if cwd_changed || old_needle != needle {
            self.selected = 0;
        }
        if let Some(find) = &mut self.find {
            find.needle = needle;
            find.stem = query_stem(&query);
            find.cycling = false;
        }
    }

    fn end_find(&mut self, cancel: bool) {
        if self.find.is_none() {
            return;
        }
        let anchor = self
            .find
            .as_ref()
            .map(|find| find.anchor.clone())
            .unwrap_or_default();
        let kept = self.visible_selection_name();
        self.find = None;
        if cancel && self.cwd != anchor {
            self.cwd = anchor;
            self.reload();
            self.selected = 0;
            return;
        }
        self.select_name(kept);
    }

    fn complete_tab(&mut self, delta: isize) {
        let names = self.visible_names();
        let Some(find) = &self.find else {
            return;
        };
        let Some(cycled) = cycle_match(
            &names,
            self.selected,
            &find.stem,
            &find.query,
            find.cycling,
            delta,
        ) else {
            return;
        };
        self.selected = cycled.index;
        if let Some(find) = &mut self.find {
            find.query = cycled.query;
            find.cycling = true;
        }
    }

    fn move_shown(&mut self, delta: isize) {
        let count = self.visible_count();
        move_index(&mut self.selected, count, delta);
        if let Some(find) = &mut self.find {
            find.cycling = false;
        }
    }

    fn visible_names(&self) -> Vec<String> {
        let needle = self
            .find
            .as_ref()
            .map(|find| find.needle.clone())
            .unwrap_or_default();
        self.entries
            .iter()
            .filter(|entry| name_matches(&entry.name, &needle))
            .map(|entry| entry.name.clone())
            .collect()
    }

    fn visible_count(&self) -> usize {
        let needle = self
            .find
            .as_ref()
            .map(|find| find.needle.clone())
            .unwrap_or_default();
        self.entries
            .iter()
            .filter(|entry| name_matches(&entry.name, &needle))
            .count()
    }

    fn visible_selection_name(&self) -> Option<String> {
        let needle = self
            .find
            .as_ref()
            .map(|find| find.needle.clone())
            .unwrap_or_default();
        self.entries
            .iter()
            .filter(|entry| name_matches(&entry.name, &needle))
            .nth(self.selected)
            .map(|entry| entry.name.clone())
    }

    fn select_name(&mut self, name: Option<String>) {
        let Some(name) = name else {
            return;
        };
        if let Some(index) = self.entries.iter().position(|entry| entry.name == name) {
            self.selected = index;
        }
    }
}

impl PutOp {
    fn label(&self) -> &str {
        match self {
            PutOp::Mkdir(path) | PutOp::File { dest: path, .. } => path,
        }
    }
}

fn list_host_dir(dir: &Path) -> std::result::Result<Vec<HostEntry>, String> {
    let mut entries = Vec::new();
    let read =
        std::fs::read_dir(dir).map_err(|err| format!("cannot read {}: {err}", dir.display()))?;
    for entry in read {
        let entry = entry.map_err(|err| format!("cannot read {}: {err}", dir.display()))?;
        let path = entry.path();
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let kind = match entry.file_type() {
            Ok(kind) if kind.is_dir() => HostKind::Dir,
            Ok(kind) if kind.is_file() => HostKind::File,
            Ok(kind) if kind.is_symlink() => match entry.metadata() {
                Ok(meta) if meta.is_dir() => HostKind::Dir,
                Ok(meta) if meta.is_file() => HostKind::File,
                _ => HostKind::Other,
            },
            _ => HostKind::Other,
        };
        let bytes = if kind == HostKind::File {
            entry.metadata().map(|meta| meta.len()).unwrap_or(0)
        } else {
            0
        };
        entries.push(HostEntry {
            path,
            name,
            kind,
            bytes,
        });
    }
    entries.sort_by(|left, right| {
        kind_rank(left.kind)
            .cmp(&kind_rank(right.kind))
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(entries)
}

fn kind_rank(kind: HostKind) -> u8 {
    match kind {
        HostKind::Dir => 0,
        HostKind::File => 1,
        HostKind::Other => 2,
    }
}

#[derive(Debug)]
struct PutPlan {
    ops: Vec<PutOp>,
    skipped: Vec<PathBuf>,
}

fn plan_puts(volume_cwd: &str, marked: &[PathBuf]) -> std::result::Result<PutPlan, String> {
    if marked.is_empty() {
        return Err("nothing selected".into());
    }
    let mut paths = marked.to_vec();
    paths.sort();
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    for path in paths {
        let meta = match target_metadata(&path)? {
            Some(meta) => meta,
            None => {
                return Err(format!("{} is a broken symbolic link", path.display()));
            }
        };
        if meta.is_dir() {
            let name = utf8_file_name(&path)?;
            let dest = volume_child(volume_cwd, &name)?;
            dirs.push(dest.clone());
            let mut seen = HashSet::new();
            walk_host_dir(&path, &dest, &mut dirs, &mut files, &mut skipped, &mut seen)?;
        } else if meta.is_file() {
            let name = utf8_file_name(&path)?;
            files.push((path, volume_child(volume_cwd, &name)?));
        } else {
            return Err(format!("{} is not a file or directory", path.display()));
        }
    }
    Ok(PutPlan {
        ops: assemble_puts(dirs, files)?,
        skipped,
    })
}

fn target_metadata(path: &Path) -> std::result::Result<Option<std::fs::Metadata>, String> {
    let listed =
        std::fs::symlink_metadata(path).map_err(|err| format!("{}: {err}", path.display()))?;
    if listed.file_type().is_symlink() {
        return Ok(std::fs::metadata(path).ok());
    }
    Ok(Some(listed))
}

fn walk_host_dir(
    dir: &Path,
    volume_dir: &str,
    dirs: &mut Vec<String>,
    files: &mut Vec<(PathBuf, String)>,
    skipped: &mut Vec<PathBuf>,
    seen: &mut HashSet<(u64, u64)>,
) -> std::result::Result<(), String> {
    let meta = std::fs::metadata(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    if !seen.insert((meta.dev(), meta.ino())) {
        return Ok(());
    }
    let mut children = std::fs::read_dir(dir)
        .map_err(|err| format!("cannot read {}: {err}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|err| format!("cannot read {}: {err}", dir.display()))?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let name = utf8_file_name(&path)?;
        let dest = volume_child(volume_dir, &name)?;
        let Some(meta) = target_metadata(&path)? else {
            skipped.push(path);
            continue;
        };
        if meta.is_dir() {
            let id = (meta.dev(), meta.ino());
            if seen.contains(&id) {
                continue;
            }
            dirs.push(dest.clone());
            walk_host_dir(&path, &dest, dirs, files, skipped, seen)?;
        } else if meta.is_file() {
            files.push((path, dest));
        }
    }
    Ok(())
}

enum Planned {
    Dir,
    File(Option<(u64, u64)>),
}

fn assemble_puts(
    dirs: Vec<String>,
    files: Vec<(PathBuf, String)>,
) -> std::result::Result<Vec<PutOp>, String> {
    let mut taken: BTreeMap<String, Planned> = BTreeMap::new();
    let mut ops = Vec::new();
    for dir in dirs {
        match taken.get(&dir) {
            Some(Planned::File(_)) => {
                return Err(format!("cannot store a file and a directory at {dir}"));
            }
            Some(Planned::Dir) => continue,
            None => {
                taken.insert(dir.clone(), Planned::Dir);
                ops.push(PutOp::Mkdir(dir));
            }
        }
    }
    for (host, dest) in files {
        let id = std::fs::metadata(&host)
            .ok()
            .map(|meta| (meta.dev(), meta.ino()));
        match taken.get(&dest) {
            Some(Planned::Dir) => {
                return Err(format!("cannot store a file and a directory at {dest}"));
            }
            Some(Planned::File(existing)) if *existing == id && id.is_some() => continue,
            Some(Planned::File(_)) => {
                return Err(format!(
                    "{dest} would be written by more than one selected file"
                ));
            }
            None => {
                taken.insert(dest.clone(), Planned::File(id));
                ops.push(PutOp::File { host, dest });
            }
        }
    }
    Ok(ops)
}

fn utf8_file_name(path: &Path) -> std::result::Result<String, String> {
    let Some(name) = path.file_name() else {
        return Err(format!("{} has no file name", path.display()));
    };
    name.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{} is not valid UTF-8", path.display()))
}

fn volume_child(dir: &str, name: &str) -> std::result::Result<String, String> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!("cannot store {name}"));
    }
    if name.len() > 255 {
        return Err(format!("{name} is longer than 255 bytes"));
    }
    if name
        .bytes()
        .any(|byte| byte < 0x20 || byte == 0x7f || byte == b'/')
    {
        return Err(format!(
            "{name} contains a character the volume cannot store"
        ));
    }
    let path = child_path(dir, name);
    if path.len() > 4096 {
        return Err(format!("{path} is longer than 4096 bytes"));
    }
    Ok(path)
}

fn put_notice(files: usize, dirs: usize, dest: &str, skipped: &[PathBuf]) -> String {
    let mut text = put_summary(files, dirs, dest);
    match skipped {
        [] => {}
        [one] => {
            let name = one
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| one.display().to_string());
            text.push_str(&format!("; skipped broken symbolic link {name}"));
        }
        many => text.push_str(&format!("; skipped {} broken symbolic links", many.len())),
    }
    text
}

fn put_summary(files: usize, dirs: usize, dest: &str) -> String {
    match (files, dirs) {
        (0, 1) => format!("created 1 directory in {dest}"),
        (0, dirs) => format!("created {dirs} directories in {dest}"),
        (1, 0) => format!("wrote 1 file into {dest}"),
        (files, 0) => format!("wrote {files} files into {dest}"),
        (files, dirs) => format!("stored {files} files and {dirs} directories in {dest}"),
    }
}

enum CopyStop {
    Done,
    Cancel(u64),
    Close(u64),
    Failed(String),
}

enum PutStop {
    Run,
    Cancel,
    Close,
}

fn put_stop() -> Result<PutStop> {
    while event::poll(Duration::ZERO)? {
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if key.code == KeyCode::Esc {
            return Ok(PutStop::Close);
        }
        let cancel = key.code == KeyCode::Char('q')
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c'));
        if cancel {
            return Ok(PutStop::Cancel);
        }
    }
    Ok(PutStop::Run)
}

fn user_home() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            let path = PathBuf::from(home);
            if path.is_dir() {
                return Some(std::fs::canonicalize(&path).unwrap_or(path));
            }
        }
    }
    passwd_home()
}

fn passwd_home() -> Option<PathBuf> {
    let uid = super::euid();
    // getpwuid returns a pointer into libc's static password storage.
    let entry = unsafe { libc::getpwuid(uid) };
    if entry.is_null() {
        return None;
    }
    let dir = unsafe { (*entry).pw_dir };
    if dir.is_null() {
        return None;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(dir) }.to_bytes();
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    if !path.is_dir() {
        return None;
    }
    Some(std::fs::canonicalize(&path).unwrap_or(path))
}

fn draw_host(frame: &mut Frame, area: Rect, volume_cwd: &str, host: &HostBrowser) {
    let query = if host.confirm.is_none() {
        host.find.as_ref().map(|find| find.query.as_str())
    } else {
        None
    };
    let area = list_area(frame, area, query);
    let block = host_block(volume_cwd, host);
    if !host.error.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(host.error.clone(), fg(BAD)))
                .block(block)
                .style(surface())
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let needle = host
        .find
        .as_ref()
        .map(|find| find.needle.clone())
        .unwrap_or_default();
    if host.entries.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("This directory is empty.", fg(MUTED)))
                .block(block)
                .style(surface()),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = host
        .entries
        .iter()
        .filter(|entry| name_matches(&entry.name, &needle))
        .map(|entry| {
            let mark = match host.job {
                HostJob::Get => None,
                HostJob::Put => Some(host.marked.contains(&entry.path)),
            };
            ListItem::new(host_row(entry, mark))
        })
        .collect();
    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("No matches.", fg(MUTED)))
                .block(block)
                .style(surface()),
            area,
        );
        return;
    }
    let mut state = ListState::default();
    state.select(Some(host.selected.min(items.len() - 1)));
    let list = List::new(items)
        .block(block)
        .style(surface())
        .highlight_style(highlight());
    frame.render_stateful_widget(list, area, &mut state);
}

fn list_area(frame: &mut Frame, area: Rect, query: Option<&str>) -> Rect {
    let Some(query) = query else {
        return area;
    };
    let [bar, list] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    draw_find_bar(frame, bar, query);
    list
}

fn draw_find_bar(frame: &mut Frame, area: Rect, query: &str) {
    if area.is_empty() {
        return;
    }
    let line = Line::from(vec![
        Span::styled(" / ", fg(SAGE).add_modifier(Modifier::BOLD)),
        Span::styled(query.to_string(), fg(TEXT)),
        Span::styled(" ", highlight()),
    ]);
    frame.render_widget(Paragraph::new(line).style(raised()), area);
}

fn host_block(volume_cwd: &str, host: &HostBrowser) -> Block<'static> {
    let place = host.cwd.display().to_string();
    let count = host.marked.len();
    let mut block = shell(format!(" {place} "), surface());
    if host.job == HostJob::Get {
        let count = host.getting.len();
        let noun = if count == 1 { "file" } else { "files" };
        block = block
            .title(Line::from(Span::styled(format!(" {count} {noun} "), fg(SAGE))).right_aligned());
    } else if count == 0 {
        block = block.title(Line::from(format!(" into {volume_cwd} ")).right_aligned());
    } else {
        block = block.title(
            Line::from(Span::styled(format!(" {count} selected "), fg(SAGE))).right_aligned(),
        );
    }
    block
}

fn host_row(entry: &HostEntry, marked: Option<bool>) -> Line<'static> {
    let (kind, kind_style, size) = match entry.kind {
        HostKind::Dir => ("dir", fg(SAGE), String::new()),
        HostKind::File => ("file", fg(MUTED), human_bytes(entry.bytes)),
        HostKind::Other => ("·", fg(MUTED), String::new()),
    };
    let mut spans = Vec::new();
    if let Some(marked) = marked {
        let (mark, mark_style) = if marked {
            ("●", fg(SAGE))
        } else {
            ("○", fg(MUTED))
        };
        spans.push(Span::styled(format!("{mark}  "), mark_style));
    }
    spans.push(Span::styled(format!("{kind:<4}  "), kind_style));
    spans.push(Span::styled(format!("{size:>8}  "), fg(MUTED)));
    spans.push(Span::styled(entry.name.clone(), fg(TEXT)));
    Line::from(spans)
}

fn draw_put_progress(frame: &mut Frame, area: Rect, volume_cwd: &str, progress: &HostProgress) {
    let ratio = if progress.total == 0 {
        1.0
    } else {
        (progress.done as f64 / progress.total as f64).clamp(0.0, 1.0)
    };
    draw_meter(
        frame,
        area,
        "Copy",
        &progress.current,
        &format!("into {volume_cwd}"),
        ratio,
        &format!("{} / {}", progress.done, progress.total),
    );
}

impl GetReview {
    fn move_cursor(&mut self, delta: isize) {
        let count = self.files.len();
        if count == 0 {
            self.selected = 0;
            return;
        }
        if delta == 1 || delta == -1 {
            let next = self.selected as isize + delta;
            self.selected = if next < 0 {
                count - 1
            } else if (next as usize) >= count {
                0
            } else {
                next as usize
            };
            return;
        }
        if delta > 0 {
            self.selected = (self.selected + delta as usize).min(count - 1);
        } else {
            self.selected = self.selected.saturating_sub(delta.unsigned_abs());
        }
    }

    fn remove_selected(&mut self) {
        if self.files.is_empty() {
            return;
        }
        let index = self.selected.min(self.files.len() - 1);
        self.files.remove(index);
        if self.selected >= self.files.len() {
            self.selected = self.files.len().saturating_sub(1);
        }
        if duplicate_get_name(&self.files).is_none() {
            self.error.clear();
        }
    }
}

fn order_get_picks(files: &mut [GetPick]) {
    files.sort_by(|left, right| left.size.cmp(&right.size).then(left.name.cmp(&right.name)));
}

fn duplicate_get_name(files: &[GetPick]) -> Option<&str> {
    let mut seen = BTreeSet::new();
    for file in files {
        if !seen.insert(file.name.as_str()) {
            return Some(file.name.as_str());
        }
    }
    None
}

fn get_display_order(items: &[GetItem]) -> Vec<usize> {
    let mut top = Vec::new();
    let mut bottom = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match item.phase {
            GetPhase::Pending | GetPhase::Active => top.push(index),
            GetPhase::Done | GetPhase::Failed => bottom.push(index),
        }
    }
    top.extend(bottom);
    top
}

fn draw_get_review(frame: &mut Frame, area: Rect, review: &GetReview) {
    let count = review.files.len();
    let noun = if count == 1 { "file" } else { "files" };
    let mut block = shell(format!(" Get {count} {noun} "), surface());
    if !review.error.is_empty() {
        block = block.title(
            Line::from(Span::styled(format!(" {} ", review.error), fg(BAD))).right_aligned(),
        );
    }
    if review.files.is_empty() {
        let message = if review.error.is_empty() {
            "No files.".to_string()
        } else {
            review.error.clone()
        };
        let style = if review.error.is_empty() {
            fg(MUTED)
        } else {
            fg(BAD)
        };
        frame.render_widget(
            Paragraph::new(Span::styled(message, style))
                .block(block)
                .style(surface()),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = review
        .files
        .iter()
        .map(|file| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:>8}  ", human_bytes(file.size)), fg(MUTED)),
                Span::styled(file.src.clone(), fg(TEXT)),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(block)
        .style(surface())
        .highlight_style(highlight());
    let mut state = ListState::default();
    state.select(Some(review.selected.min(review.files.len() - 1)));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_get_dest_dialog(frame: &mut Frame, area: Rect, dest: &Path) {
    let popup = dialog_area(area, 68, 8);
    frame.render_widget(Clear, popup);
    let block = shell(" Get ", raised());
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    if inner.is_empty() {
        return;
    }
    let path = fit(&dest.display().to_string(), inner.width as usize);
    let lines = vec![
        Line::from(Span::styled(path, fg(TEXT).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled("enter ", fg(SAGE).add_modifier(Modifier::BOLD)),
            Span::styled("move", fg(TEXT)),
            Span::styled("    ", fg(MUTED)),
            Span::styled("esc ", fg(SAGE).add_modifier(Modifier::BOLD)),
            Span::styled("cancel", fg(TEXT)),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).style(raised()), inner);
}

fn draw_get_progress(frame: &mut Frame, items: &[GetItem], dest: &Path, running: bool) {
    paint_screen(frame);
    let [header, body, help] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    paint_banner(frame, header, "Get", &dest.display().to_string());
    let block = shell(" Download ", surface());
    let inner = block.inner(body);
    frame.render_widget(block, body);
    if !inner.is_empty() {
        let order = get_display_order(items);
        let height = inner.height as usize;
        let active = order
            .iter()
            .position(|&index| matches!(items[index].phase, GetPhase::Active))
            .unwrap_or(0);
        let start = if order.len() <= height {
            0
        } else {
            active.min(order.len() - height)
        };
        for row in 0..height {
            let Some(&index) = order.get(start + row) else {
                break;
            };
            let line_area = Rect {
                x: inner.x,
                y: inner.y + row as u16,
                width: inner.width,
                height: 1,
            };
            paint_get_line(frame, line_area, &items[index]);
        }
    }
    let keys: &[(&str, &str)] = if running {
        &[("esc", "cancel"), ("q", "cancel")]
    } else {
        &[("enter", "close"), ("esc", "close"), ("q", "close")]
    };
    frame.render_widget(Paragraph::new(keymap(keys)).style(chrome(false)), help);
}

fn paint_get_line(frame: &mut Frame, area: Rect, item: &GetItem) {
    let ratio = match item.phase {
        GetPhase::Active => Some(get_ratio(item.written, item.size)),
        _ => None,
    };
    let idle = match item.phase {
        GetPhase::Done => fg(SAGE).bg(INK),
        GetPhase::Failed => fg(BAD).bg(INK),
        _ => surface(),
    };
    paint_line_bar(
        frame,
        area,
        &get_row_text(item, area.width as usize),
        ratio,
        idle,
    );
}

fn get_ratio(written: u64, total: u64) -> f64 {
    if total == 0 {
        1.0
    } else {
        (written as f64 / total as f64).clamp(0.0, 1.0)
    }
}

fn get_percent(written: u64, total: u64) -> u64 {
    if total == 0 {
        100
    } else {
        (written.saturating_mul(100) / total).min(100)
    }
}

fn get_row_text(item: &GetItem, width: usize) -> String {
    let status = match item.phase {
        GetPhase::Active => format!("{:>3}%", get_percent(item.written, item.size)),
        GetPhase::Done => "done".to_string(),
        GetPhase::Failed => "fail".to_string(),
        GetPhase::Pending => "    ".to_string(),
    };
    if width <= 4 {
        return fit(&status, width);
    }
    let size_w = 8.min(width.saturating_sub(6));
    let rest = width.saturating_sub(4 + 2 + 2 + size_w + 2);
    let name_w = rest / 2;
    let dest_w = rest.saturating_sub(name_w);
    let name = pad_end(&fit(&item.name, name_w), name_w);
    let size = pad_start(&fit(&human_bytes(item.size), size_w), size_w);
    let dest = fit(&item.dest.display().to_string(), dest_w);
    let mut text = format!("{status}  {name}  {size}  {dest}");
    let count = text.chars().count();
    if count < width {
        text.push_str(&" ".repeat(width - count));
    } else if count > width {
        text = fit(&text, width);
    }
    text
}

fn pad_end(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count >= width {
        return fit(text, width);
    }
    let mut out = text.to_string();
    out.push_str(&" ".repeat(width - count));
    out
}

fn pad_start(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count >= width {
        return fit(text, width);
    }
    let mut out = " ".repeat(width - count);
    out.push_str(text);
    out
}

fn paint_line_bar(frame: &mut Frame, area: Rect, text: &str, ratio: Option<f64>, idle: Style) {
    if area.is_empty() {
        return;
    }
    let filled = match ratio {
        Some(ratio) => {
            ((f64::from(area.width) * ratio.clamp(0.0, 1.0)).round() as u16).min(area.width)
        }
        None => 0,
    };
    let chars: Vec<char> = text.chars().collect();
    let buf = frame.buffer_mut();
    for x in 0..area.width {
        let style = if ratio.is_some() {
            bar_style(x < filled)
        } else {
            idle
        };
        let symbol = chars.get(x as usize).copied().unwrap_or(' ');
        buf[(area.x + x, area.y)].set_char(symbol).set_style(style);
    }
}

fn get_stop() -> Result<bool> {
    while event::poll(Duration::ZERO)? {
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        let cancel = key.code == KeyCode::Esc
            || key.code == KeyCode::Char('q')
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c'));
        if cancel {
            return Ok(true);
        }
    }
    Ok(false)
}

fn wait_get_close(terminal: &mut Term, items: &[GetItem], dest: &Path) -> Result<()> {
    loop {
        terminal.draw(|frame| draw_get_progress(frame, items, dest, false))?;
        let event = event::read()?;
        let Event::Key(key) = event else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q') => return Ok(()),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_password_cursor_stays_under_the_label() {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        for bullets in ["", "●●"] {
            terminal
                .draw(|frame| {
                    paint_screen(frame);
                    draw_secret(frame, frame.area(), "Unlock", "/dev/sda", bullets);
                })
                .unwrap();
            assert_painted(terminal.backend());
            let buffer = terminal.backend().buffer();
            let label = row_containing(buffer, "Password").expect("password label");
            let cursor = (0..buffer.area.height)
                .find(|y| (0..buffer.area.width).any(|x| buffer[(x, *y)].bg == ACCENT))
                .expect("password cursor");
            assert_eq!(
                cursor,
                label + 1,
                "cursor for {bullets:?} is not on the input line\n{}",
                terminal.backend()
            );
        }
    }

    #[test]
    fn paths_and_sizes() {
        assert_eq!(child_path("/", "notes"), "/notes");
        assert_eq!(child_path("/path1", "file"), "/path1/file");
        assert_eq!(parent_path("/path1/file"), "/path1");
        assert_eq!(parent_path("/path1"), "/");
        assert_eq!(parent_path("/"), "/");
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1536), "1.5 K");
    }

    #[test]
    fn path_steps_split_a_filter_from_directories() {
        let check = |query: &str, absolute: bool, enter: &[&str], needle: &str| {
            let steps = path_steps(query);
            assert_eq!(steps.absolute, absolute, "{query}");
            assert_eq!(steps.enter, enter, "{query}");
            assert_eq!(steps.needle, needle, "{query}");
        };
        check("", false, &[], "");
        check("dir", false, &[], "dir");
        check("dir/", false, &["dir"], "");
        check("dir1/dir2", false, &["dir1"], "dir2");
        check("dir1/dir2/", false, &["dir1", "dir2"], "");
        check("/", true, &[], "");
        check("/dir1", true, &[], "dir1");
        check("/dir1/", true, &["dir1"], "");
        check("/dir1/dir2", true, &["dir1"], "dir2");
        check("/dir1/dir2/", true, &["dir1", "dir2"], "");
        check("../", false, &[".."], "");
        check("./dir", false, &["."], "dir");
        check("dir1//dir2", false, &["dir1"], "dir2");
        check("//", true, &[], "");
    }

    #[test]
    fn follow_path_enters_on_a_trailing_slash() {
        let tmp = Tmp::new();
        let dir1 = tmp.path.join("dir1");
        let dir2 = dir1.join("dir2");
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(dir1.join("file.txt"), "x").unwrap();
        std::os::unix::fs::symlink(&dir1, tmp.path.join("linkdir")).unwrap();

        let (cwd, needle) = follow_path(&tmp.path, "dir1");
        assert_eq!((cwd, needle), (tmp.path.clone(), "dir1".to_string()));

        let (cwd, needle) = follow_path(&tmp.path, "dir1/");
        assert_eq!((cwd, needle), (dir1.clone(), String::new()));

        let (cwd, needle) = follow_path(&tmp.path, "dir1/dir2");
        assert_eq!((cwd, needle), (dir1.clone(), "dir2".to_string()));

        let (cwd, needle) = follow_path(&tmp.path, "dir1/dir2/");
        assert_eq!((cwd, needle), (dir2.clone(), String::new()));

        let (cwd, needle) = follow_path(&tmp.path, "missing/");
        assert_eq!((cwd, needle), (tmp.path.clone(), "missing".to_string()));

        let (cwd, needle) = follow_path(&tmp.path, "dir1/file.txt/nope");
        assert_eq!((cwd, needle), (dir1.clone(), "file.txt".to_string()));

        let (cwd, needle) = follow_path(&dir2, "../");
        assert_eq!((cwd, needle), (dir1.clone(), String::new()));

        let (cwd, needle) = follow_path(&tmp.path, "./dir1/");
        assert_eq!((cwd, needle), (dir1, String::new()));

        let link = tmp.path.join("linkdir");
        let (cwd, needle) = follow_path(&tmp.path, "linkdir/");
        assert_eq!((cwd, needle), (link, String::new()));

        let absolute = format!("{}/", dir2.display());
        let (cwd, needle) = follow_path(&tmp.path, &absolute);
        assert_eq!((cwd, needle), (dir2, String::new()));

        let (cwd, needle) = follow_path(&tmp.path, "/");
        assert_eq!((cwd, needle), (PathBuf::from("/"), String::new()));
    }

    #[test]
    fn host_find_filters_until_a_slash_then_navigates() {
        let tmp = Tmp::new();
        let dir1 = tmp.path.join("dir1");
        let dir2 = dir1.join("dir2");
        std::fs::create_dir(&dir1).unwrap();
        std::fs::create_dir(&dir2).unwrap();
        std::fs::create_dir(dir1.join("dir3")).unwrap();
        std::fs::write(dir1.join("notes.txt"), "n").unwrap();
        std::fs::create_dir(tmp.path.join("dir1-extra")).unwrap();
        let mut host = HostBrowser {
            cwd: tmp.path.clone(),
            entries: Vec::new(),
            selected: 0,
            marked: BTreeSet::new(),
            error: String::new(),
            progress: None,
            job: HostJob::Put,
            getting: Vec::new(),
            confirm: None,
            find: None,
        };
        host.reload();
        let type_find = |host: &mut HostBrowser, text: &str| {
            for ch in text.chars() {
                host.find_push(ch);
            }
        };

        host.begin_find();
        type_find(&mut host, "dir1");
        assert_eq!(host.cwd, tmp.path);
        assert_eq!(host.find.as_ref().unwrap().needle, "dir1");
        assert_eq!(
            shown_names(&host),
            vec!["dir1".to_string(), "dir1-extra".to_string()]
        );
        host.find_push('/');
        assert_eq!(host.cwd, dir1);
        assert!(host.find.as_ref().unwrap().needle.is_empty());
        assert_eq!(
            shown_names(&host),
            vec![
                "dir2".to_string(),
                "dir3".to_string(),
                "notes.txt".to_string()
            ]
        );
        type_find(&mut host, "dir2/");
        assert_eq!(host.cwd, dir2);
        host.end_find(true);
        assert!(host.find.is_none());
        assert_eq!(host.cwd, tmp.path);

        host.begin_find();
        type_find(&mut host, "dir1/notes");
        assert_eq!(host.cwd, dir1);
        assert_eq!(shown_names(&host), vec!["notes.txt".to_string()]);
        host.move_shown(1);
        assert_eq!(host.selected, 0);
        host.end_find(false);
        assert!(host.find.is_none());
        assert_eq!(host.cwd, dir1);
        assert_eq!(host.entries[host.selected].name, "notes.txt");

        host.begin_find();
        type_find(&mut host, "notes.txt/");
        assert_eq!(host.cwd, dir1);
        assert_eq!(host.find.as_ref().unwrap().needle, "notes.txt");
        host.end_find(true);

        host.begin_find();
        type_find(&mut host, "dir2/");
        assert_eq!(host.cwd, dir2);
        host.find_pop();
        assert_eq!(host.cwd, dir1);
        assert_eq!(host.find.as_ref().unwrap().needle, "dir2");
        host.end_find(true);
        assert_eq!(host.cwd, dir1);

        host.begin_find();
        type_find(&mut host, "../");
        assert_eq!(host.cwd, tmp.path);
        host.end_find(false);
        assert_eq!(host.cwd, tmp.path);
    }

    #[test]
    fn tab_cycles_filtered_names_and_keeps_the_filter() {
        let names = vec!["dir1".to_string(), "dir1-extra".to_string()];
        let first = cycle_match(&names, 0, "", "dir", false, 1).unwrap();
        assert_eq!(first.index, 0);
        assert_eq!(first.query, "dir1");
        let second = cycle_match(&names, first.index, "", &first.query, true, 1).unwrap();
        assert_eq!(second.index, 1);
        assert_eq!(second.query, "dir1-extra");
        let back = cycle_match(&names, second.index, "", &second.query, true, -1).unwrap();
        assert_eq!(back.index, 0);
        assert_eq!(back.query, "dir1");
        let wrapped = cycle_match(&names, 0, "", "dir", false, -1).unwrap();
        assert_eq!(wrapped.index, 1);
        assert_eq!(wrapped.query, "dir1-extra");
        let nested = cycle_match(
            &["dir2".into(), "dir3".into()],
            0,
            "dir1/",
            "dir1/d",
            false,
            1,
        )
        .unwrap();
        assert_eq!(nested.query, "dir1/dir2");
        assert_eq!(query_stem("dir1/d"), "dir1/");
        assert_eq!(query_stem("/dir1/"), "/dir1/");
        assert_eq!(query_stem("dir"), "");

        let tmp = Tmp::new();
        let dir1 = tmp.path.join("dir1");
        std::fs::create_dir(&dir1).unwrap();
        std::fs::create_dir(dir1.join("dir2")).unwrap();
        std::fs::create_dir(dir1.join("dir3")).unwrap();
        std::fs::create_dir(tmp.path.join("dir1-extra")).unwrap();
        std::fs::create_dir(tmp.path.join("other")).unwrap();
        let mut host = HostBrowser {
            cwd: tmp.path.clone(),
            entries: Vec::new(),
            selected: 0,
            marked: BTreeSet::new(),
            error: String::new(),
            progress: None,
            job: HostJob::Put,
            getting: Vec::new(),
            confirm: None,
            find: None,
        };
        host.reload();
        host.begin_find();
        for ch in "dir".chars() {
            host.find_push(ch);
        }
        assert_eq!(
            shown_names(&host),
            vec!["dir1".to_string(), "dir1-extra".to_string()]
        );
        host.complete_tab(1);
        let find = host.find.as_ref().unwrap();
        assert_eq!(find.query, "dir1");
        assert_eq!(find.needle, "dir");
        assert_eq!(host.selected, 0);
        assert_eq!(
            shown_names(&host),
            vec!["dir1".to_string(), "dir1-extra".to_string()]
        );
        host.complete_tab(1);
        assert_eq!(host.find.as_ref().unwrap().query, "dir1-extra");
        assert_eq!(host.selected, 1);
        host.complete_tab(-1);
        assert_eq!(host.find.as_ref().unwrap().query, "dir1");
        assert_eq!(host.selected, 0);
        host.find_push('x');
        assert_eq!(host.find.as_ref().unwrap().query, "dir1x");
        assert_eq!(host.find.as_ref().unwrap().needle, "dir1x");
        assert!(shown_names(&host).is_empty());

        host.end_find(true);
        host.begin_find();
        for ch in "dir1/d".chars() {
            host.find_push(ch);
        }
        assert_eq!(host.cwd, dir1);
        host.complete_tab(1);
        let find = host.find.as_ref().unwrap();
        assert_eq!(find.query, "dir1/dir2");
        assert_eq!(find.needle, "d");
        assert_eq!(
            shown_names(&host),
            vec!["dir2".to_string(), "dir3".to_string()]
        );
        host.complete_tab(1);
        assert_eq!(host.find.as_ref().unwrap().query, "dir1/dir3");
        assert_eq!(host.cwd, dir1);
    }

    #[test]
    fn host_find_paints_the_query_and_filters_names() {
        let host = HostBrowser {
            cwd: PathBuf::from("/work"),
            entries: vec![
                HostEntry {
                    path: PathBuf::from("/work/notes"),
                    name: "notes".into(),
                    kind: HostKind::Dir,
                    bytes: 0,
                },
                HostEntry {
                    path: PathBuf::from("/work/nope"),
                    name: "nope".into(),
                    kind: HostKind::Dir,
                    bytes: 0,
                },
                HostEntry {
                    path: PathBuf::from("/work/image"),
                    name: "image".into(),
                    kind: HostKind::File,
                    bytes: 4,
                },
            ],
            selected: 0,
            marked: BTreeSet::new(),
            error: String::new(),
            progress: None,
            job: HostJob::Put,
            getting: Vec::new(),
            confirm: None,
            find: Some(HostFind {
                anchor: PathBuf::from("/work"),
                query: "/not".into(),
                needle: "not".into(),
                stem: "/".into(),
                cycling: false,
            }),
        };
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(60, 14)).unwrap();
        terminal
            .draw(|frame| {
                paint_screen(frame);
                let [header, body, help] = Layout::vertical([
                    Constraint::Length(1),
                    Constraint::Min(0),
                    Constraint::Length(1),
                ])
                .areas(frame.area());
                paint_banner(frame, header, "Put", "/work");
                draw_host(frame, body, "/docs", &host);
                frame.render_widget(Paragraph::new(find_keymap()).style(chrome(false)), help);
            })
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("/not"), "{view}");
        assert!(view.contains("notes"), "{view}");
        assert!(!view.contains("nope"), "{view}");
        assert!(!view.contains("image"), "{view}");

        let missed = HostBrowser {
            find: Some(HostFind {
                anchor: PathBuf::from("/work"),
                query: "zzz".into(),
                needle: "zzz".into(),
                stem: String::new(),
                cycling: false,
            }),
            ..host
        };
        terminal
            .draw(|frame| {
                paint_screen(frame);
                draw_host(frame, frame.area(), "/docs", &missed);
            })
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("No matches."), "{view}");
        assert!(view.contains("zzz"), "{view}");
        assert!(!view.contains("notes"), "{view}");

        let empty = HostBrowser {
            entries: Vec::new(),
            ..missed
        };
        terminal
            .draw(|frame| {
                paint_screen(frame);
                draw_host(frame, frame.area(), "/docs", &empty);
            })
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("This directory is empty."), "{view}");
        assert!(view.contains("zzz"), "{view}");
    }

    #[test]
    fn disk_list_uses_dev_paths() {
        for disk in list_disks() {
            assert!(disk.path.starts_with("/dev/"), "{}", disk.path);
            assert!(disk.bytes > 0, "{}", disk.path);
        }
    }

    #[test]
    fn every_frame_paints_the_screen() {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(40, 12)).unwrap();
        let app = App::new();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        assert!(
            terminal.backend().to_string().contains("HDNFS"),
            "{}",
            terminal.backend()
        );

        terminal
            .draw(|frame| draw_init_progress(frame, "/tmp/vault.img", "writing", 512, 1024))
            .unwrap();
        let backend = terminal.backend();
        assert_painted(backend);
        let view = backend.to_string();
        assert!(view.contains("Writing free space"), "{view}");
        assert!(view.contains("512 / 1024 MiB"), "{view}");
        assert!(view.contains("50%"), "{view}");
        assert!(
            backend
                .buffer()
                .content
                .iter()
                .any(|cell| cell.bg == ACCENT),
            "progress bar has no filled cells:\n{view}"
        );
        assert!(
            backend.buffer().content.iter().any(|cell| cell.bg == TRACK),
            "progress bar has no track:\n{view}"
        );

        let mut small = Terminal::new(ratatui::backend::TestBackend::new(20, 6)).unwrap();
        small.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(small.backend());
        small
            .draw(|frame| draw_init_progress(frame, "/tmp/vault.img", "sealing", 8, 8))
            .unwrap();
        assert_painted(small.backend());
    }

    fn assert_painted(backend: &ratatui::backend::TestBackend) {
        let buffer = backend.buffer();
        let mut misses = Vec::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                if buffer[(x, y)].bg == Color::Reset {
                    misses.push((x, y));
                }
            }
        }
        assert!(misses.is_empty(), "unpainted cells {misses:?}\n{backend}");
    }

    #[test]
    fn put_browser_opens_at_home() {
        let Some(home) = user_home() else {
            return;
        };
        let host = HostBrowser::start();
        assert_eq!(host.cwd, home);
        assert!(host.marked.is_empty());
    }

    #[test]
    fn host_browser_lists_dirs_first_and_space_toggles() {
        let tmp = Tmp::new();
        std::fs::write(tmp.path.join("b.txt"), "b").unwrap();
        std::fs::create_dir(tmp.path.join("notes")).unwrap();
        std::fs::write(tmp.path.join(".hidden"), "h").unwrap();
        let mut host = HostBrowser {
            cwd: tmp.path.clone(),
            entries: Vec::new(),
            selected: 0,
            marked: BTreeSet::new(),
            error: String::new(),
            progress: None,
            job: HostJob::Put,
            getting: Vec::new(),
            confirm: None,
            find: None,
        };
        host.reload();
        let names: Vec<_> = host
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["notes", ".hidden", "b.txt"]);
        assert_eq!(host.entries[0].kind, HostKind::Dir);
        host.selected = 2;
        host.toggle_selected().unwrap();
        host.selected = 0;
        host.toggle_selected().unwrap();
        host.toggle_selected().unwrap();
        assert_eq!(host.marked.len(), 1);
        assert!(host.marked.contains(&tmp.path.join("b.txt")));
    }

    #[test]
    fn plan_puts_files_and_a_directory_tree() {
        let tmp = Tmp::new();
        std::fs::write(tmp.path.join("a.txt"), "a").unwrap();
        std::fs::write(tmp.path.join("b.txt"), "b").unwrap();
        let notes = tmp.path.join("notes");
        std::fs::create_dir(&notes).unwrap();
        std::fs::write(notes.join("c.txt"), "c").unwrap();
        std::fs::create_dir(notes.join("empty")).unwrap();
        std::fs::create_dir(notes.join("sub")).unwrap();
        std::fs::write(notes.join("sub").join("d.txt"), "d").unwrap();
        std::os::unix::fs::symlink("c.txt", notes.join("link.txt")).unwrap();
        let outside = tmp.path.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "s").unwrap();
        std::os::unix::fs::symlink(&outside, notes.join("linked-dir")).unwrap();
        std::os::unix::fs::symlink(&notes, notes.join("loop")).unwrap();

        let files = plan_puts("/docs", &[tmp.path.join("a.txt"), tmp.path.join("b.txt")]).unwrap();
        assert_eq!(
            dests(&files.ops),
            vec!["/docs/a.txt".to_string(), "/docs/b.txt".to_string()]
        );

        let tree = plan_puts("/docs", &[notes.clone()]).unwrap();
        assert_eq!(
            dests(&tree.ops),
            vec![
                "/docs/notes".to_string(),
                "/docs/notes/empty".to_string(),
                "/docs/notes/linked-dir".to_string(),
                "/docs/notes/sub".to_string(),
                "/docs/notes/c.txt".to_string(),
                "/docs/notes/link.txt".to_string(),
                "/docs/notes/linked-dir/secret.txt".to_string(),
                "/docs/notes/sub/d.txt".to_string(),
            ]
        );

        let mixed = plan_puts("/docs", &[tmp.path.join("a.txt"), notes.clone()]).unwrap();
        assert!(dests(&mixed.ops).contains(&"/docs/a.txt".to_string()));
        assert!(dests(&mixed.ops).contains(&"/docs/notes/c.txt".to_string()));

        let broken = notes.join("balenaEtcher");
        std::os::unix::fs::symlink("/home/runner/work/etcher/etcher/missing", &broken).unwrap();
        let with_broken = plan_puts("/docs", &[notes]).unwrap();
        assert!(dests(&with_broken.ops).contains(&"/docs/notes/c.txt".to_string()));
        assert!(!dests(&with_broken.ops)
            .iter()
            .any(|path| path.ends_with("balenaEtcher")));
        assert_eq!(with_broken.skipped.len(), 1);
        let direct = plan_puts("/docs", &[broken]).unwrap_err();
        assert!(direct.contains("broken symbolic link"), "{direct}");

        let same_name = tmp.path.join("other");
        std::fs::create_dir(&same_name).unwrap();
        std::fs::write(same_name.join("a.txt"), "other").unwrap();
        let err =
            plan_puts("/docs", &[tmp.path.join("a.txt"), same_name.join("a.txt")]).unwrap_err();
        assert!(err.contains("/docs/a.txt"), "{err}");

        std::fs::write(tmp.path.join("bad\nname"), "x").unwrap();
        let err = plan_puts("/", &[tmp.path.join("bad\nname")]).unwrap_err();
        assert!(err.contains("cannot store"), "{err}");
    }

    #[test]
    fn host_browser_paints_the_screen() {
        let mut marked = BTreeSet::new();
        marked.insert(PathBuf::from("/tmp/a.txt"));
        let host = HostBrowser {
            cwd: PathBuf::from("/tmp"),
            entries: vec![
                HostEntry {
                    path: PathBuf::from("/tmp/notes"),
                    name: "notes".into(),
                    kind: HostKind::Dir,
                    bytes: 0,
                },
                HostEntry {
                    path: PathBuf::from("/tmp/a.txt"),
                    name: "a.txt".into(),
                    kind: HostKind::File,
                    bytes: 12,
                },
            ],
            selected: 1,
            marked,
            error: String::new(),
            progress: None,
            job: HostJob::Put,
            getting: Vec::new(),
            confirm: None,
            find: None,
        };
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(60, 14)).unwrap();
        terminal
            .draw(|frame| {
                paint_screen(frame);
                let [body, status, help] = Layout::vertical([
                    Constraint::Min(3),
                    Constraint::Length(1),
                    Constraint::Length(1),
                ])
                .areas(frame.area());
                draw_host(frame, body, "/docs", &host);
                frame.render_widget(Paragraph::new("").style(chrome(false)), status);
                frame.render_widget(Paragraph::new("space select").style(chrome(false)), help);
            })
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("●"), "{view}");
        assert!(view.contains("a.txt"), "{view}");
        assert!(view.contains("notes"), "{view}");
        assert!(view.contains("1 selected"), "{view}");
    }

    #[test]
    fn get_list_is_smallest_first_and_refuses_duplicate_names() {
        let mut files = vec![
            GetPick {
                src: "/docs/b.txt".into(),
                name: "b.txt".into(),
                size: 50,
            },
            GetPick {
                src: "/docs/a.txt".into(),
                name: "a.txt".into(),
                size: 10,
            },
            GetPick {
                src: "/other/c.txt".into(),
                name: "c.txt".into(),
                size: 10,
            },
        ];
        order_get_picks(&mut files);
        let names: Vec<_> = files.iter().map(|file| file.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "c.txt", "b.txt"]);
        assert_eq!(duplicate_get_name(&files), None);

        let duplicated = vec![
            GetPick {
                src: "/docs/a.txt".into(),
                name: "a.txt".into(),
                size: 1,
            },
            GetPick {
                src: "/other/a.txt".into(),
                name: "a.txt".into(),
                size: 2,
            },
        ];
        assert_eq!(duplicate_get_name(&duplicated), Some("a.txt"));

        let dest = Path::new("/tmp/out");
        let mut items = vec![
            get_item("a.txt", dest, 10, GetPhase::Pending),
            get_item("c.txt", dest, 10, GetPhase::Pending),
            get_item("b.txt", dest, 50, GetPhase::Active),
        ];
        assert_eq!(get_display_order(&items), vec![0, 1, 2]);
        items[0].phase = GetPhase::Done;
        assert_eq!(get_display_order(&items), vec![1, 2, 0]);
        items[2].phase = GetPhase::Failed;
        assert_eq!(get_display_order(&items), vec![1, 0, 2]);
        assert_eq!(get_percent(0, 0), 100);
        assert_eq!(get_percent(42, 100), 42);
        assert_eq!(get_percent(150, 100), 100);
    }

    #[test]
    fn get_progress_paints_the_active_bar() {
        let dest = PathBuf::from("/tmp/out");
        let items = vec![
            GetItem {
                name: "notes.txt".into(),
                src: "/notes.txt".into(),
                dest: dest.join("notes.txt"),
                size: 100,
                written: 42,
                phase: GetPhase::Active,
                error: String::new(),
            },
            GetItem {
                name: "tiny.txt".into(),
                src: "/tiny.txt".into(),
                dest: dest.join("tiny.txt"),
                size: 4,
                written: 4,
                phase: GetPhase::Done,
                error: String::new(),
            },
        ];
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(72, 12)).unwrap();
        terminal
            .draw(|frame| draw_get_progress(frame, &items, &dest, true))
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("notes.txt"), "{view}");
        assert!(view.contains("tiny.txt"), "{view}");
        assert!(view.contains("42%"), "{view}");
        assert!(view.contains("done"), "{view}");
        assert!(view.contains("100 B"), "{view}");
        assert!(view.contains("/tmp/out/notes.txt"), "{view}");
        let buffer = terminal.backend().buffer();
        let notes_row = row_containing(buffer, "notes.txt").expect(&view);
        let tiny_row = row_containing(buffer, "tiny.txt").expect(&view);
        assert!(
            notes_row < tiny_row,
            "finished file stays below the active one\n{view}"
        );
        assert!(
            (0..buffer.area.width).any(|x| buffer[(x, notes_row)].bg == ACCENT),
            "active line has no progress fill\n{view}"
        );
        assert!(
            (0..buffer.area.width).any(|x| buffer[(x, notes_row)].bg == TRACK),
            "active line has no remaining track\n{view}"
        );
        assert!(
            (0..buffer.area.width).all(|x| buffer[(x, tiny_row)].bg != ACCENT),
            "finished line still paints a progress bar\n{view}"
        );
    }

    #[test]
    fn get_review_page_lists_full_paths_and_r_removes_one() {
        let mut review = GetReview {
            files: vec![
                GetPick {
                    src: "/docs/a.txt".into(),
                    name: "a.txt".into(),
                    size: 1536,
                },
                GetPick {
                    src: "/docs/nested/b.txt".into(),
                    name: "b.txt".into(),
                    size: 50,
                },
            ],
            selected: 0,
            error: String::new(),
        };
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(72, 12)).unwrap();
        terminal
            .draw(|frame| {
                paint_screen(frame);
                let [header, body, help] = Layout::vertical([
                    Constraint::Length(1),
                    Constraint::Min(0),
                    Constraint::Length(1),
                ])
                .areas(frame.area());
                paint_banner(frame, header, "Get", "/docs");
                draw_get_review(frame, body, &review);
                frame.render_widget(
                    Paragraph::new(keymap(&[
                        ("j k", "move"),
                        ("r", "remove"),
                        ("enter", "confirm"),
                        ("esc", "cancel"),
                    ]))
                    .style(chrome(false)),
                    help,
                );
            })
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("1.5 K"), "{view}");
        assert!(view.contains("/docs/a.txt"), "{view}");
        assert!(view.contains("/docs/nested/b.txt"), "{view}");
        assert!(!view.contains("○") && !view.contains("●"), "{view}");
        let buffer = terminal.backend().buffer();
        let row = row_containing(buffer, "/docs/a.txt").expect(&view);
        assert!(
            (0..buffer.area.width).any(|x| buffer[(x, row)].bg == ACCENT),
            "the cursor line is not highlighted\n{view}"
        );

        review.selected = 1;
        review.remove_selected();
        assert_eq!(review.files.len(), 1);
        assert_eq!(review.files[0].src, "/docs/a.txt");
        assert_eq!(review.selected, 0);
        review.move_cursor(1);
        assert_eq!(review.selected, 0);
    }

    #[test]
    fn get_directory_browser_hides_marks_and_confirms_the_path() {
        let host = HostBrowser {
            cwd: PathBuf::from("/home/sveinn/out"),
            entries: vec![
                HostEntry {
                    path: PathBuf::from("/home/sveinn/out/notes"),
                    name: "notes".into(),
                    kind: HostKind::Dir,
                    bytes: 0,
                },
                HostEntry {
                    path: PathBuf::from("/home/sveinn/out/a.txt"),
                    name: "a.txt".into(),
                    kind: HostKind::File,
                    bytes: 12,
                },
            ],
            selected: 0,
            marked: BTreeSet::new(),
            error: String::new(),
            progress: None,
            job: HostJob::Get,
            getting: vec![GetPick {
                src: "/docs/a.txt".into(),
                name: "a.txt".into(),
                size: 12,
            }],
            confirm: Some(PathBuf::from("/home/sveinn/out")),
            find: None,
        };
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(72, 16)).unwrap();
        terminal
            .draw(|frame| {
                paint_screen(frame);
                let [body, help] = Layout::vertical([Constraint::Min(3), Constraint::Length(1)])
                    .areas(frame.area());
                draw_host(frame, body, "/docs", &host);
                if let Some(dest) = &host.confirm {
                    draw_get_dest_dialog(frame, body, dest);
                }
                frame.render_widget(
                    Paragraph::new(keymap(&[("enter", "move"), ("esc", "cancel")]))
                        .style(chrome(false)),
                    help,
                );
            })
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("/home/sveinn/out"), "{view}");
        assert!(view.contains("move"), "{view}");
        assert!(view.contains("cancel"), "{view}");
        assert!(!view.contains('○') && !view.contains('●'), "{view}");
    }

    fn get_item(name: &str, dest: &Path, size: u64, phase: GetPhase) -> GetItem {
        GetItem {
            name: name.into(),
            src: format!("/{name}"),
            dest: dest.join(name),
            size,
            written: 0,
            phase,
            error: String::new(),
        }
    }

    fn shown_names(host: &HostBrowser) -> Vec<String> {
        let needle = host
            .find
            .as_ref()
            .map(|find| find.needle.clone())
            .unwrap_or_default();
        host.entries
            .iter()
            .filter(|entry| name_matches(&entry.name, &needle))
            .map(|entry| entry.name.clone())
            .collect()
    }

    fn row_containing(buffer: &ratatui::buffer::Buffer, needle: &str) -> Option<u16> {
        for y in 0..buffer.area.height {
            let mut line = String::new();
            for x in 0..buffer.area.width {
                line.push_str(buffer[(x, y)].symbol());
            }
            if line.contains(needle) {
                return Some(y);
            }
        }
        None
    }

    fn dests(ops: &[PutOp]) -> Vec<String> {
        ops.iter()
            .map(|op| match op {
                PutOp::Mkdir(path) => path.clone(),
                PutOp::File { dest, .. } => dest.clone(),
            })
            .collect()
    }

    struct Tmp {
        path: PathBuf,
    }

    impl Tmp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "hdnfs-host-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
