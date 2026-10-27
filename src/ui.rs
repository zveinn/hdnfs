use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, IsTerminal, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ratatui::crossterm::cursor::Hide;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap,
};
use ratatui::{Frame, Terminal};
use zeroize::Zeroize;

use hdnfs::{
    block_device_bytes, disable_process_dumps, format_unix_utc, has_volume_magic, init_volume,
    parse_size, validate_password, DirEntry, Error, HealthReport, InitOptions, KdfParams, Kind,
    LockMode, Result, SecretString, Stat, Volume,
};

type Term = Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>;

pub fn run() -> Result<()> {
    if !io::stdout().is_terminal() {
        return Err(Error::Message("hdnfs ui needs a terminal".into()));
    }
    disable_process_dumps()
        .map_err(|err| Error::Message(format!("failed to disable process dumps: {err}")))?;
    save_termios();
    install_job_signals();
    let mut terminal = ratatui::try_init().map_err(|err| Error::Message(err.to_string()))?;
    let mut app = App::new();
    let result = app.event_loop(&mut terminal);
    ratatui::restore();
    result
}

struct App {
    screen: Screen,
    /// Shortcut whose auto-repeat must not be typed into the next field.
    ignore_repeat: Option<KeyCode>,
    /// Blocking work. The event loop only draws, polls, and applies results.
    /// The loader bar stays hidden until [`JOB_CURTAIN`].
    job: Option<Job>,
    /// Dismissible failure for disk open, unlock, and initialization.
    alert: Option<String>,
    pending_ssh: Option<ArmedConnect>,
    /// ssh is dialing. The terminal stays with the TUI until authentication.
    dial: Option<Dial>,
    /// Last painted frame. A parked job has no volume to redraw, so the loader
    /// bar is painted on this copy.
    last_frame: RefCell<Option<ratatui::buffer::Buffer>>,
}

struct ArmedConnect {
    tag: String,
    session: crate::ssh::Session,
}

struct Dial {
    tag: String,
    child: crate::ssh::SshProc,
    started: Instant,
}

enum Screen {
    Pick(Pick),
    Sudo(Sudo),
    Unlock(Unlock),
    Setup(Setup),
    Passwd(PasswdForm),
    Browse(Browse),
    /// The open volume is on a worker. The job screen covers this.
    Parked,
}

struct Pick {
    disks: Vec<Disk>,
    selected: usize,
    editing: bool,
    path: String,
}

#[derive(Clone)]
struct Disk {
    path: String,
    bytes: u64,
    model: String,
    removable: bool,
    partition: bool,
    file: bool,
}

struct Sudo {
    path: PathBuf,
    password: Hidden,
    /// What to open once this user can read the device.
    after: AfterAccess,
}

/// Current password, then the new one twice. Enter submits.
struct PasswdForm {
    path: PathBuf,
    current: Hidden,
    next: Hidden,
    again: Hidden,
    cursor: usize,
}

struct Unlock {
    path: PathBuf,
    password: Hidden,
}

struct Setup {
    path: PathBuf,
    /// Editable path. Used when [`FieldId::Path`] is on the form.
    path_text: String,
    block: bool,
    fields: Vec<FieldId>,
    cursor: usize,
    capacity: Option<u64>,
    confirm: String,
    size: String,
    password: Hidden,
    again: Hidden,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldId {
    Path,
    Confirm,
    Size,
    Password,
    Again,
}

struct Browse {
    volume_path: PathBuf,
    /// `None` while a `/` search is listing this volume on a background thread.
    volume: Option<Volume>,
    cwd: String,
    entries: Vec<DirEntry>,
    selected: usize,
    marked: BTreeSet<String>,
    free: String,
    prompt: Prompt,
    notice_pending: Option<(bool, String)>,
    find: Option<VolumeFind>,
    /// When a `/` search should walk and list. Prefix filters do not set this.
    find_list_at: Option<Instant>,
    /// Background directory walk. The find field stays editable while it runs.
    find_walk: Option<FindWalk>,
    /// Enter, Tab, or Esc pressed while a walk is still running.
    find_after: Option<FindThen>,
    view: BrowseView,
    menu: VolumeMenu,
    ssh: SshLists,
    deferred: Option<Deferred>,
    armed_session: Option<ArmedConnect>,
    overlay: Option<Overlay>,
}

enum Prompt {
    None,
    Line {
        title: &'static str,
        value: String,
    },
    Delete {
        path: String,
        kind: Kind,
    },
    Note {
        title: String,
        body: String,
    },
    GetReview(GetReview),
    Host(HostBrowser),
    /// Delete confirmation. One line: retype the tag.
    SshForm(SshForm),
    /// Create, add, and generate. Every field is on the page at once.
    PageForm(PageForm),
    HostEdit(HostEditor),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrowseView {
    Files,
    Hosts,
    Keys,
    Passwords,
}

const MENU_ITEMS: [BrowseView; 4] = [
    BrowseView::Files,
    BrowseView::Hosts,
    BrowseView::Keys,
    BrowseView::Passwords,
];
const MENU_LABELS: [&str; 4] = ["files", "hosts", "keys", "passwords"];

struct VolumeMenu {
    open: bool,
    cursor: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SshPane {
    Hosts,
    Keys,
    Passwords,
}

struct SshLists {
    pane: SshPane,
    hosts: Vec<crate::ssh::HostRow>,
    keys: Vec<crate::ssh::KeyRow>,
    passwords: Vec<crate::ssh::PasswordRow>,
    selected: usize,
}

/// Retype a tag to delete it. This stays one line.
struct SshForm {
    pane: SshPane,
    tag: String,
    value: String,
}

/// One labeled input on a page form.
struct FormField {
    label: &'static str,
    value: String,
    secret: bool,
    limit: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormKind {
    CreateKey,
    AddKey,
    PasswordAdd,
    PasswordGenerate,
}

struct PageForm {
    title: &'static str,
    hint: &'static str,
    fields: Vec<FormField>,
    cursor: usize,
    error: String,
    kind: FormKind,
}

struct FormIssue {
    cursor: usize,
    message: String,
    clear_secrets: bool,
}

struct HostDraft {
    tag: String,
    key: String,
    hostname: String,
    user: String,
    port: String,
    timeout: String,
    options: Vec<String>,
    /// Rewrite an existing host. Create leaves this false.
    update: bool,
}

/// Every field of one host, open at once. Create edits the tag. Edit keeps it fixed.
#[derive(Clone)]
struct HostEditor {
    tag: String,
    key: String,
    hostname: String,
    user: String,
    port: String,
    timeout: String,
    options: Vec<String>,
    /// Create: `0` tag, then key, hostname, user, port, timeout, and options.
    /// Edit: `0` key, then the same tail. The last index is an empty option row.
    cursor: usize,
    error: String,
    create: bool,
}

enum Apply {
    Stay,
    Quit,
    Disks,
    Connect(String),
    HostPrompt,
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
    /// Query last applied. A later edit in this directory only filters.
    resolved: String,
    /// The last walk entered every completed path component.
    landed: bool,
}

struct HostFind {
    anchor: PathBuf,
    query: String,
    needle: String,
    stem: String,
    cycling: bool,
    /// Query last applied. A later edit in this directory only filters.
    resolved: String,
    /// The last walk entered every completed path component.
    landed: bool,
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
    OpenDir,
    UpDir,
    ReloadDir,
    Home,
    FindEnd(bool),
    FindApply(FindThen),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FindThen {
    Close,
    Cancel,
    Tab(isize),
}

struct FindWalk {
    rx: mpsc::Receiver<FindWalkOut>,
}

enum FindWalkOut {
    Host(HostWalk),
    Volume(VolumeWalk),
}

struct HostWalk {
    query: String,
    cwd: PathBuf,
    entries: Vec<HostEntry>,
    needle: String,
    landed: bool,
    error: String,
}

struct VolumeWalk {
    query: String,
    volume: Volume,
    cwd: String,
    entries: Vec<DirEntry>,
    needle: String,
    landed: bool,
    free: String,
    error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FindNote {
    Unchanged,
    Filtered,
    Walk,
}

#[derive(Clone, Copy)]
enum GetPhase {
    Pending,
    Active,
    Done,
    Failed,
}

#[derive(Clone)]
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

/// `0` running, `1` stop the operation, `2` stop and close the host browser.
type CancelFlag = Arc<AtomicU8>;

/// A fast read should not flash the loader bar. The previous frame stays up until this.
const JOB_CURTAIN: Duration = Duration::from_secs(1);

/// `/` search lists a directory only after typing has stopped this long.
const FIND_LIST_WAIT: Duration = Duration::from_millis(300);

/// One character, advanced once per event-loop poll while a job is running.
const LOADER_FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const LOADER_STEP_MS: u128 = 80;

struct Job {
    title: String,
    detail: String,
    started: Instant,
    cancel: CancelFlag,
    watch: Option<Arc<InitWatch>>,
    paint: Paint,
    /// The worker owns the open volume and must send it back.
    retain: bool,
    rx: mpsc::Receiver<JobOut>,
}

struct LoaderView {
    title: String,
    detail: String,
    elapsed: Duration,
}

struct InitWatch {
    stage: Mutex<String>,
    done: AtomicU64,
    total: AtomicU64,
}

impl InitWatch {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            stage: Mutex::new(String::new()),
            done: AtomicU64::new(0),
            total: AtomicU64::new(0),
        })
    }

    fn set(&self, stage: &str, done: u64, total: u64) {
        *self.stage.lock().unwrap_or_else(|err| err.into_inner()) = stage.to_string();
        self.done.store(done, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (String, u64, u64) {
        let stage = self
            .stage
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        (
            stage,
            self.done.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
        )
    }
}

enum Paint {
    Plain,
    Health,
    Backup,
    Get(Arc<Mutex<GetPaint>>),
    Copy,
    Init,
}

#[derive(Clone)]
struct GetPaint {
    items: Vec<GetItem>,
    dest: PathBuf,
}

enum JobOut {
    Probe(ProbeOut),
    Disks(Vec<Disk>),
    Unlocked {
        browse: std::result::Result<Browse, String>,
    },
    Initialized {
        browse: std::result::Result<Browse, String>,
    },
    Restored(Browse),
    PasswordChanged {
        result: std::result::Result<(), String>,
    },
}

enum ProbeOut {
    Sudo { path: PathBuf, after: AfterAccess },
    Unlock(PathBuf),
    Setup(Setup),
    Passwd(PathBuf),
    Failed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterAccess {
    Open,
    Initialize,
    Passwd,
}

struct Deferred {
    title: String,
    detail: String,
    watch: Option<Arc<InitWatch>>,
    cancel: CancelFlag,
    paint: Paint,
    work: Box<dyn FnOnce(&mut Browse) + Send>,
}

enum Overlay {
    Health(HealthView),
    Get { items: Vec<GetItem>, dest: PathBuf },
}

struct JobStart {
    title: String,
    detail: String,
    watch: Option<Arc<InitWatch>>,
    cancel: CancelFlag,
    paint: Paint,
    retain: bool,
}

thread_local! {
    static ON_WORKER: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    static INLINE_JOBS: Cell<bool> = const { Cell::new(true) };
    static JOB_HOLD: Cell<Option<mpsc::Receiver<()>>> = const { Cell::new(None) };
}

fn jobs_inline() -> bool {
    #[cfg(test)]
    {
        INLINE_JOBS.with(Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn run_here() -> bool {
    jobs_inline() || ON_WORKER.with(Cell::get)
}

fn take_job_hold() -> Option<mpsc::Receiver<()>> {
    #[cfg(test)]
    {
        JOB_HOLD.with(Cell::take)
    }
    #[cfg(not(test))]
    {
        None
    }
}

struct WorkerFlag;

impl WorkerFlag {
    fn enter() -> Self {
        ON_WORKER.with(|flag| flag.set(true));
        Self
    }
}

impl Drop for WorkerFlag {
    fn drop(&mut self) {
        ON_WORKER.with(|flag| flag.set(false));
    }
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            screen: Screen::Pick(Pick {
                disks: Vec::new(),
                selected: 0,
                editing: false,
                path: String::new(),
            }),
            ignore_repeat: None,
            job: None,
            alert: None,
            pending_ssh: None,
            dial: None,
            last_frame: RefCell::new(None),
        };
        app.refresh_disks();
        app
    }

    /// Drop auto-repeat of a shortcut that just changed screens.
    fn absorb_repeat(&mut self, key: &KeyEvent) -> bool {
        if key.kind == KeyEventKind::Repeat && self.ignore_repeat == Some(key.code) {
            return true;
        }
        if key.kind != KeyEventKind::Repeat {
            self.ignore_repeat = None;
        }
        false
    }

    fn event_loop(&mut self, terminal: &mut Term) -> Result<()> {
        loop {
            let resumed = take_resume();
            if resumed {
                resume_terminal(terminal)?;
            }
            claim_foreground();
            self.poll_find_walk();
            self.launch_find_list();
            self.launch_deferred();
            self.poll_job(None);
            self.spawn_armed_ssh();
            self.drive_dial(terminal)?;
            // A parked volume has nothing new to paint. Leaving the last frame
            // up avoids a flash while a directory opens. After the curtain, the
            // loader bar is drawn on that frame. A dial shows the bar at once.
            if resumed || self.dial.is_some() || !self.hold_frame() {
                terminal.draw(|frame| self.draw(frame))?;
            }
            let timeout = self.frame_wait_ms();
            if let Some(event) = next_event(timeout)? {
                if self.on_event(event, terminal)? {
                    return Ok(());
                }
            }
        }
    }

    fn note(&mut self, _bad: bool, _text: impl Into<String>) {}

    fn on_event(&mut self, event: Event, terminal: &mut Term) -> Result<bool> {
        if self.dial.is_some() {
            if let Event::Key(key) = event {
                if key.kind != KeyEventKind::Release && cancel_code(&key).is_some() {
                    self.cancel_dial()?;
                }
            }
            return Ok(false);
        }
        let key = match event {
            Event::Key(key) if key.kind != KeyEventKind::Release => key,
            Event::Paste(text) => {
                if self.busy() {
                    return Ok(false);
                }
                self.paste(&text);
                return Ok(false);
            }
            _ => return Ok(false),
        };
        if self.alert.take().is_some() {
            return Ok(false);
        }
        if self.job.is_some() {
            if let Some(code) = cancel_code(&key) {
                self.cancel_job(code);
            }
            return Ok(false);
        }
        if self.overlay_open() {
            if cancel_code(&key).is_some()
                || matches!(key.code, KeyCode::Enter | KeyCode::Char('q'))
            {
                self.dismiss_overlay();
            }
            return Ok(false);
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Ok(true);
        }
        match &mut self.screen {
            Screen::Pick(_) => self.on_pick(key),
            Screen::Sudo(_) => self.on_sudo(key),
            Screen::Unlock(_) => self.on_unlock(key),
            Screen::Setup(_) => self.on_setup(key, terminal),
            Screen::Passwd(_) => self.on_passwd(key),
            Screen::Browse(_) => self.on_browse(key, terminal),
            Screen::Parked => Ok(false),
        }
    }

    fn busy(&self) -> bool {
        self.job.is_some() || self.alert.is_some() || self.overlay_open()
    }

    fn overlay_open(&self) -> bool {
        matches!(self.screen, Screen::Browse(ref browse) if browse.overlay.is_some())
    }

    fn dismiss_overlay(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        let overlay = browse.overlay.take();
        if matches!(overlay, Some(Overlay::Health(_))) {
            browse.reload();
        }
    }

    fn refresh_disks(&mut self) {
        self.start_job(
            JobStart {
                title: "Reading disks".into(),
                detail: String::new(),
                watch: None,
                cancel: Arc::new(AtomicU8::new(0)),
                paint: Paint::Plain,
                retain: false,
            },
            || JobOut::Disks(list_pick_entries()),
        );
    }

    fn start_plain<F>(&mut self, title: &str, detail: String, work: F)
    where
        F: FnOnce() -> JobOut + Send + 'static,
    {
        self.start_job(
            JobStart {
                title: title.into(),
                detail,
                watch: None,
                cancel: Arc::new(AtomicU8::new(0)),
                paint: Paint::Plain,
                retain: false,
            },
            work,
        );
    }

    fn start_job<F>(&mut self, spec: JobStart, work: F)
    where
        F: FnOnce() -> JobOut + Send + 'static,
    {
        if self.job.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::clone(&spec.cancel);
        let retain = spec.retain;
        let hold = take_job_hold();
        let held = hold.is_some();
        let task = move || {
            if let Some(hold) = hold {
                let _ = hold.recv();
            }
            let _worker = WorkerFlag::enter();
            if !retain && cancel.load(Ordering::Relaxed) != 0 {
                return;
            }
            let _ = tx.send(work());
        };
        if jobs_inline() {
            task();
        } else {
            // Spawned threads inherit this mask. Ctrl-Z has to land on the
            // event-loop thread; a worker that ran the handler would stop alone.
            block_stop_signal();
            thread::spawn(task);
            unblock_stop_signal();
        }
        self.job = Some(Job {
            title: spec.title,
            detail: spec.detail,
            started: Instant::now(),
            cancel: spec.cancel,
            watch: spec.watch,
            paint: spec.paint,
            retain: spec.retain,
            rx,
        });
        if jobs_inline() {
            self.poll_job(None);
        } else if !held {
            // Fast reads finish before the next frame, so the screen does not flash.
            self.poll_job(Some(Duration::from_millis(16)));
        }
    }

    fn poll_job(&mut self, wait: Option<Duration>) {
        let Some(job) = &self.job else {
            return;
        };
        let canceled = job.cancel.load(Ordering::Relaxed) != 0;
        let received = if let Some(wait) = wait {
            match job.rx.recv_timeout(wait) {
                Ok(out) => Some(out),
                Err(mpsc::RecvTimeoutError::Timeout) => return,
                Err(mpsc::RecvTimeoutError::Disconnected) => None,
            }
        } else {
            match job.rx.try_recv() {
                Ok(out) => Some(out),
                Err(mpsc::TryRecvError::Empty) => return,
                Err(mpsc::TryRecvError::Disconnected) => None,
            }
        };
        self.job = None;
        if let Some(out) = received {
            self.apply_job(out, canceled);
        }
    }

    fn cancel_job(&mut self, code: u8) {
        let Some(job) = &self.job else {
            return;
        };
        job.cancel.store(code.max(1), Ordering::Relaxed);
        if job.retain {
            return;
        }
        let init = matches!(job.paint, Paint::Init);
        self.job = None;
        if init {
            self.alert = Some("initialization canceled".into());
        }
    }

    fn apply_job(&mut self, out: JobOut, canceled: bool) {
        match out {
            JobOut::Probe(probe) => self.apply_probe(probe),
            JobOut::Disks(disks) => {
                if let Screen::Pick(pick) = &mut self.screen {
                    let current = pick.disks.get(pick.selected).map(|disk| disk.path.clone());
                    let selected = current
                        .and_then(|path| disks.iter().position(|disk| disk.path == path))
                        .unwrap_or(0);
                    pick.disks = disks;
                    pick.selected = selected.min(pick.disks.len().saturating_sub(1));
                }
            }
            JobOut::Unlocked { browse } => match browse {
                Ok(browse) => {
                    self.screen = Screen::Browse(browse);
                    self.take_browse_notice();
                }
                Err(text) => {
                    self.clear_secret();
                    self.alert = Some(text);
                }
            },
            JobOut::Initialized { browse } => match browse {
                Ok(browse) => {
                    self.screen = Screen::Browse(browse);
                    self.take_browse_notice();
                }
                Err(text) => self.alert = Some(text),
            },
            JobOut::Restored(mut browse) => {
                if canceled {
                    browse.armed_session = None;
                }
                self.pending_ssh = browse.armed_session.take();
                self.screen = Screen::Browse(browse);
            }
            JobOut::PasswordChanged { result } => match result {
                Ok(()) => {
                    self.alert = Some("password changed".into());
                    self.back_to_pick();
                }
                Err(text) => {
                    if let Screen::Passwd(form) = &mut self.screen {
                        form.clear();
                    }
                    self.alert = Some(text);
                }
            },
        }
    }

    fn apply_probe(&mut self, probe: ProbeOut) {
        match probe {
            ProbeOut::Sudo { path, after } => {
                self.screen = Screen::Sudo(Sudo {
                    path,
                    password: Hidden::default(),
                    after,
                });
            }
            ProbeOut::Unlock(path) => {
                self.screen = Screen::Unlock(Unlock {
                    path,
                    password: Hidden::default(),
                });
            }
            ProbeOut::Setup(setup) => self.screen = Screen::Setup(setup),
            ProbeOut::Passwd(path) => self.screen = Screen::Passwd(PasswdForm::new(path)),
            ProbeOut::Failed(text) => {
                self.clear_secret();
                self.alert = Some(text);
            }
        }
    }

    fn clear_secret(&mut self) {
        match &mut self.screen {
            Screen::Sudo(sudo) => sudo.password.clear(),
            Screen::Unlock(unlock) => unlock.password.clear(),
            Screen::Passwd(form) => form.clear(),
            _ => {}
        }
    }

    fn frame_wait_ms(&self) -> u64 {
        if self.dial.is_some() {
            return 16;
        }
        if self.job.is_some() {
            return 80;
        }
        if self.find_walking() {
            return 16;
        }
        let base = 200;
        let Screen::Browse(browse) = &self.screen else {
            return base;
        };
        let Some(due) = browse.find_list_at else {
            return base;
        };
        let left = due.saturating_duration_since(Instant::now()).as_millis() as u64;
        left.min(base)
    }

    fn find_walking(&self) -> bool {
        matches!(&self.screen, Screen::Browse(browse) if browse.find_walk.is_some())
    }

    fn poll_find_walk(&mut self) {
        let outcome = {
            let Screen::Browse(browse) = &mut self.screen else {
                return;
            };
            let Some(walk) = browse.find_walk.as_ref() else {
                return;
            };
            match walk.rx.try_recv() {
                Ok(outcome) => Some(Ok(outcome)),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => Some(Err(())),
            }
        };
        let Some(outcome) = outcome else {
            return;
        };
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.find_walk = None;
        match outcome {
            Ok(outcome) => browse.apply_find_walk(outcome),
            Err(()) => {
                if browse.volume.is_none() {
                    browse.fail_msg("directory listing stopped");
                }
            }
        }
    }

    /// Runs a deferred `/` directory walk once typing has stopped.
    fn launch_find_list(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        if browse.find_walk.is_some() || self.job.is_some() {
            return;
        }
        let due = browse.find_list_at.is_some_and(|due| Instant::now() >= due);
        if !due {
            return;
        }
        browse.find_list_at = None;
        browse.start_find_walk();
    }

    fn settle_volume_find(&mut self, then: FindThen) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.request_find_then(then);
    }

    fn settle_host_find(&mut self, then: FindThen) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.request_find_then(then);
    }

    fn launch_deferred(&mut self) {
        if self.job.is_some() {
            return;
        }
        let Screen::Browse(browse) = &self.screen else {
            return;
        };
        if browse.deferred.is_none() {
            return;
        }
        let Screen::Browse(mut browse) = std::mem::replace(&mut self.screen, Screen::Parked) else {
            return;
        };
        let Some(deferred) = browse.deferred.take() else {
            self.screen = Screen::Browse(browse);
            return;
        };
        let Deferred {
            title,
            detail,
            watch,
            cancel,
            paint,
            work,
        } = deferred;
        self.start_job(
            JobStart {
                title,
                detail,
                watch,
                cancel,
                paint,
                retain: true,
            },
            move || {
                work(&mut browse);
                JobOut::Restored(browse)
            },
        );
    }

    fn spawn_armed_ssh(&mut self) {
        let Some(armed) = self.pending_ssh.take() else {
            return;
        };
        match crate::ssh::SshProc::spawn(armed.session, &[], true) {
            Ok(child) => {
                self.dial = Some(Dial {
                    tag: armed.tag,
                    child,
                    started: Instant::now(),
                });
            }
            Err(err) => self.show_ssh_error(err.to_string()),
        }
    }

    fn drive_dial(&mut self, terminal: &mut Term) -> Result<()> {
        let polled = {
            let Some(dial) = &mut self.dial else {
                return Ok(());
            };
            dial.child.poll()?
        };
        match polled {
            crate::ssh::SshPoll::Pending => Ok(()),
            crate::ssh::SshPoll::NeedsTerminal => self.yield_for_prompt(terminal),
            crate::ssh::SshPoll::Authenticated => self.replace_with_ssh_waiter(),
            crate::ssh::SshPoll::Finished(status) => {
                let authed = crate::ssh::session_authed();
                self.dial = None;
                if authed {
                    self.exit_with_ssh_status(status);
                }
                self.show_ssh_status(status);
                Ok(())
            }
        }
    }

    /// A host-key prompt needs the terminal before authentication. Stay in this
    /// process until `ssh` authenticates or gives up, so a rejection can show
    /// the error on the host list.
    fn yield_for_prompt(&mut self, terminal: &mut Term) -> Result<()> {
        let Some(mut dial) = self.dial.take() else {
            return Ok(());
        };
        // The prompt is read before authentication. Cook the terminal so the
        // question and the answer are visible. The session pty is requested
        // later, after the same restoration.
        prepare_user_terminal();
        dial.child.take_terminal();
        loop {
            if crate::ssh::session_authed() {
                self.dial = Some(dial);
                return self.replace_with_ssh_waiter();
            }
            match dial.child.poll() {
                Ok(crate::ssh::SshPoll::Pending) => thread::sleep(Duration::from_millis(20)),
                Ok(crate::ssh::SshPoll::NeedsTerminal) => {
                    dial.child.take_terminal();
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(crate::ssh::SshPoll::Authenticated) => {
                    self.dial = Some(dial);
                    return self.replace_with_ssh_waiter();
                }
                Ok(crate::ssh::SshPoll::Finished(status)) => {
                    drop(dial);
                    resume_terminal(terminal)?;
                    self.show_ssh_status(status);
                    return Ok(());
                }
                Err(err) => {
                    drop(dial);
                    resume_terminal(terminal)?;
                    return Err(err);
                }
            }
        }
    }

    /// Authentication closed the key. Drop the volume and replace this process
    /// with a waiter of the same id so the shell keeps waiting and `ssh` keeps
    /// the terminal. This does not return to the host list.
    fn replace_with_ssh_waiter(&mut self) -> Result<()> {
        let Some(dial) = self.dial.take() else {
            return Ok(());
        };
        // ssh copies the current mode onto the remote pty after LocalCommand
        // returns. Restore the startup mode first, or the remote shell has no
        // echo and no carriage returns. detach() then lets LocalCommand finish.
        prepare_user_terminal();
        let Dial { mut child, .. } = dial;
        child.take_terminal();
        self.release_volume();
        for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            crate::ssh::set_fd_blocking(fd);
        }
        let (pid, stderr_fd) = child.detach();
        let hex = startup_termios_hex();
        let err = crate::ssh::exec_session_waiter(pid, stderr_fd, &hex);
        // exec failed. ssh is already in the foreground. Wait here and exit
        // instead of drawing the host list again. The stderr thread still
        // drains the pipe, so this side does not read it.
        eprintln!("error: failed to replace the session waiter: {err}");
        let status = crate::ssh::collect_session(pid, None, crate::ssh::decode_termios_hex(&hex));
        if let Some(note) = status.failure_note() {
            eprintln!("{note}");
        }
        std::process::exit(i32::from(status.status_number()));
    }

    fn exit_with_ssh_status(&mut self, status: crate::ssh::SshStatus) -> ! {
        self.release_volume();
        prepare_user_terminal();
        if let Some(note) = status.failure_note() {
            eprintln!("{note}");
        }
        std::process::exit(i32::from(status.status_number()));
    }

    fn release_volume(&mut self) {
        self.job = None;
        self.pending_ssh = None;
        self.alert = None;
        self.screen = Screen::Parked;
    }

    fn cancel_dial(&mut self) -> Result<()> {
        let Some(mut dial) = self.dial.take() else {
            return Ok(());
        };
        if let Err(err) = dial.child.cancel() {
            self.show_ssh_error(err.to_string());
        }
        Ok(())
    }

    fn show_ssh_status(&mut self, status: crate::ssh::SshStatus) {
        if let Some(text) = status.failure_note() {
            self.show_ssh_error(text);
        }
    }

    fn show_ssh_error(&mut self, text: String) {
        if let Screen::Browse(browse) = &mut self.screen {
            browse.note_ssh(text);
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
            Screen::Passwd(form) => form.push(ch),
            Screen::Browse(browse) => browse.push(ch),
            Screen::Pick(_) | Screen::Parked => {}
        }
    }

    fn on_pick(&mut self, key: KeyEvent) -> Result<bool> {
        if self.absorb_repeat(&key) {
            return Ok(false);
        }
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
            KeyCode::Char('r') => self.refresh_disks(),
            KeyCode::Char('/') => {
                if let Screen::Pick(pick) = &mut self.screen {
                    pick.editing = true;
                    pick.path = "/".to_string();
                }
            }
            KeyCode::Char('n') if key.kind != KeyEventKind::Repeat => {
                self.ignore_repeat = Some(KeyCode::Char('n'));
                self.screen = Screen::Setup(Setup::new_file());
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
            KeyCode::Char('i') if key.kind != KeyEventKind::Repeat => {
                self.ignore_repeat = Some(KeyCode::Char('i'));
                self.begin_initialize();
            }
            KeyCode::Char('c') if key.kind != KeyEventKind::Repeat => {
                self.ignore_repeat = Some(KeyCode::Char('c'));
                self.begin_passwd();
            }
            _ => {}
        }
        Ok(false)
    }

    fn begin_path(&mut self, path: PathBuf) {
        self.open_path(path, AfterAccess::Open);
    }

    fn begin_initialize(&mut self) {
        let path = match &self.screen {
            Screen::Pick(pick) => pick
                .disks
                .get(pick.selected)
                .map(|disk| PathBuf::from(&disk.path)),
            _ => None,
        };
        let Some(path) = path else {
            return;
        };
        self.open_path(path, AfterAccess::Initialize);
    }

    fn begin_passwd(&mut self) {
        let path = match &self.screen {
            Screen::Pick(pick) => pick
                .disks
                .get(pick.selected)
                .map(|disk| PathBuf::from(&disk.path)),
            _ => None,
        };
        let Some(path) = path else {
            return;
        };
        self.open_path(path, AfterAccess::Passwd);
    }

    fn open_path(&mut self, path: PathBuf, after: AfterAccess) {
        let detail = path.display().to_string();
        let title = match after {
            AfterAccess::Passwd => "Checking",
            _ => "Opening",
        };
        self.start_plain(title, detail, move || {
            JobOut::Probe(probe_path(path, after))
        });
    }

    fn back_to_pick(&mut self) {
        let disks = match &self.screen {
            Screen::Pick(pick) => pick.disks.clone(),
            _ => Vec::new(),
        };
        self.screen = Screen::Pick(Pick {
            disks,
            selected: 0,
            editing: false,
            path: String::new(),
        });
        self.refresh_disks();
    }

    fn on_sudo(&mut self, key: KeyEvent) -> Result<bool> {
        if self.absorb_repeat(&key) {
            return Ok(false);
        }
        match key.code {
            KeyCode::Esc => self.back_to_pick(),
            KeyCode::Backspace => {
                if let Screen::Sudo(sudo) = &mut self.screen {
                    sudo.password.pop();
                }
            }
            KeyCode::Char(ch) => self.push_char(ch),
            KeyCode::Enter => {
                let (path, password, after) = {
                    let Screen::Sudo(sudo) = &mut self.screen else {
                        return Ok(false);
                    };
                    (
                        sudo.path.clone(),
                        sudo.password.expose().to_string(),
                        sudo.after,
                    )
                };
                let detail = path.display().to_string();
                self.start_plain("Granting access", detail, move || {
                    let mut password = password;
                    let result = super::apply_sudo_password(&path, &password);
                    password.zeroize();
                    let probe = match result {
                        Ok(()) => finish_probe(path, after),
                        Err(err) => ProbeOut::Failed(err.to_string()),
                    };
                    JobOut::Probe(probe)
                });
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
            (unlock.path.clone(), unlock.password.expose().to_string())
        };
        let detail = path.display().to_string();
        self.start_plain("Unlocking", detail, move || {
            let mut password = password;
            let opened = validate_password(&password)
                .and_then(|_| Volume::open(&path, &password, LockMode::Exclusive))
                .and_then(|volume| Browse::open(path, volume));
            password.zeroize();
            JobOut::Unlocked {
                browse: opened.map_err(|err| err.to_string()),
            }
        });
    }

    fn on_passwd(&mut self, key: KeyEvent) -> Result<bool> {
        if self.absorb_repeat(&key) {
            return Ok(false);
        }
        match key.code {
            KeyCode::Esc => self.back_to_pick(),
            KeyCode::Tab | KeyCode::Down => {
                if let Screen::Passwd(form) = &mut self.screen {
                    form.cursor = (form.cursor + 1) % 3;
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                if let Screen::Passwd(form) = &mut self.screen {
                    form.cursor = (form.cursor + 2) % 3;
                }
            }
            KeyCode::Backspace => {
                if let Screen::Passwd(form) = &mut self.screen {
                    form.pop();
                }
            }
            KeyCode::Char(ch) => self.push_char(ch),
            KeyCode::Enter => self.submit_passwd(),
            _ => {}
        }
        Ok(false)
    }

    fn submit_passwd(&mut self) {
        let prepared = {
            let Screen::Passwd(form) = &mut self.screen else {
                return;
            };
            if form.next.expose() != form.again.expose() {
                Err("passwords do not match".to_string())
            } else if let Err(err) = validate_password(form.current.expose()) {
                Err(err.to_string())
            } else if let Err(err) = validate_password(form.next.expose()) {
                Err(err.to_string())
            } else {
                let path = form.path.clone();
                let current = SecretString::new(form.current.expose().to_string());
                let next = SecretString::new(form.next.expose().to_string());
                form.clear();
                Ok((path, current, next))
            }
        };
        let (path, current, next) = match prepared {
            Ok(ready) => ready,
            Err(text) => {
                self.alert = Some(text);
                return;
            }
        };
        let detail = path.display().to_string();
        let cancel = Arc::new(AtomicU8::new(0));
        let cancel_worker = Arc::clone(&cancel);
        self.start_job(
            JobStart {
                title: "Changing password".into(),
                detail,
                watch: None,
                cancel,
                paint: Paint::Plain,
                // The result has to land. Esc before the write aborts inside the
                // worker. Esc during the write still reports what happened.
                retain: true,
            },
            move || {
                let opened = Volume::open(&path, current.expose(), LockMode::Exclusive);
                let result = if cancel_worker.load(Ordering::Relaxed) != 0 {
                    Err(Error::Message("password change canceled".into()))
                } else {
                    opened.and_then(|mut volume| volume.change_password(next.expose()))
                };
                JobOut::PasswordChanged {
                    result: result.map_err(|err| err.to_string()),
                }
            },
        );
    }

    fn on_setup(&mut self, key: KeyEvent, _terminal: &mut Term) -> Result<bool> {
        if self.setup_command(key) {
            self.submit_setup()?;
        }
        Ok(false)
    }

    /// Handle one setup key. Enter returns true so the caller can submit.
    fn setup_command(&mut self, key: KeyEvent) -> bool {
        if self.absorb_repeat(&key) {
            return false;
        }
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
            KeyCode::Enter => return true,
            _ => {}
        }
        false
    }

    fn submit_setup(&mut self) -> Result<()> {
        if let Screen::Setup(setup) = &mut self.screen {
            if setup.fields.contains(&FieldId::Path) {
                if let Err(err) = setup.apply_typed_path() {
                    self.alert = Some(err);
                    return Ok(());
                }
            }
        }
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
                self.alert = Some(err);
                return Ok(());
            }
        };
        let label = plan.path.display().to_string();
        let watch = InitWatch::new();
        let watch_worker = Arc::clone(&watch);
        let cancel = Arc::new(AtomicU8::new(0));
        let cancel_worker = Arc::clone(&cancel);
        self.start_job(
            JobStart {
                title: "Initializing".into(),
                detail: label,
                watch: Some(watch),
                cancel,
                paint: Paint::Init,
                retain: false,
            },
            move || run_init(plan, watch_worker, cancel_worker),
        );
        Ok(())
    }

    fn on_browse(&mut self, key: KeyEvent, terminal: &mut Term) -> Result<bool> {
        match self.react(key) {
            Apply::HostPrompt => self.on_browse_prompt(key, terminal),
            Apply::Quit => Ok(true),
            Apply::Disks => {
                self.note(false, "");
                self.back_to_pick();
                Ok(false)
            }
            Apply::Connect(tag) => {
                self.arm_connect(tag);
                Ok(false)
            }
            Apply::Stay => {
                self.take_browse_notice();
                Ok(false)
            }
        }
    }

    /// Key handling for the open volume, except put and get pages.
    fn react(&mut self, key: KeyEvent) -> Apply {
        if self.absorb_repeat(&key) {
            return Apply::Stay;
        }
        if matches!(
            &self.screen,
            Screen::Browse(browse) if matches!(browse.prompt, Prompt::Host(_) | Prompt::GetReview(_))
        ) {
            return Apply::HostPrompt;
        }
        let prompted = matches!(
            &self.screen,
            Screen::Browse(browse) if !matches!(browse.prompt, Prompt::None)
        );
        if prompted {
            return self.drive_prompt(key);
        }
        let finding = matches!(
            &self.screen,
            Screen::Browse(browse) if browse.find.is_some()
        );
        if finding {
            let _ = self.on_volume_find(key);
            return Apply::Stay;
        }
        let menu_open = matches!(
            &self.screen,
            Screen::Browse(browse) if browse.menu.open
        );
        if menu_open {
            return self.drive_menu(key);
        }
        if key.code == KeyCode::Char('m') {
            self.open_menu();
            return Apply::Stay;
        }
        let ssh = matches!(
            &self.screen,
            Screen::Browse(browse)
                if matches!(
                    browse.view,
                    BrowseView::Hosts | BrowseView::Keys | BrowseView::Passwords
                )
        );
        if ssh {
            self.drive_ssh(key)
        } else {
            self.drive_files(key)
        }
    }

    fn open_menu(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.menu.cursor = MENU_ITEMS
            .iter()
            .position(|item| *item == browse.view)
            .unwrap_or(0);
        browse.menu.open = true;
        self.ignore_repeat = Some(KeyCode::Char('m'));
    }

    fn close_menu(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.menu.open = false;
    }

    fn move_menu(&mut self, delta: isize) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        let count = MENU_ITEMS.len() as isize;
        let next = (browse.menu.cursor as isize + delta).rem_euclid(count);
        browse.menu.cursor = next as usize;
    }

    fn confirm_menu(&mut self) {
        let (current, next) = {
            let Screen::Browse(browse) = &self.screen else {
                return;
            };
            let cursor = browse.menu.cursor.min(MENU_ITEMS.len() - 1);
            (browse.view, MENU_ITEMS[cursor])
        };
        self.close_menu();
        self.ignore_repeat = Some(KeyCode::Enter);
        if current == next {
            return;
        }
        match next {
            BrowseView::Files => self.enter_files(),
            BrowseView::Hosts => self.enter_hosts(),
            BrowseView::Keys => self.enter_keys(),
            BrowseView::Passwords => self.enter_passwords(),
        }
    }

    fn drive_menu(&mut self, key: KeyEvent) -> Apply {
        match key.code {
            KeyCode::Esc | KeyCode::Char('m') => {
                self.close_menu();
                if key.code == KeyCode::Char('m') {
                    self.ignore_repeat = Some(KeyCode::Char('m'));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_menu(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_menu(-1),
            KeyCode::Enter => self.confirm_menu(),
            KeyCode::Char('q') => return Apply::Quit,
            _ => {}
        }
        Apply::Stay
    }

    fn drive_prompt(&mut self, key: KeyEvent) -> Apply {
        let Screen::Browse(browse) = &mut self.screen else {
            return Apply::Stay;
        };
        match &browse.prompt {
            Prompt::Note { .. } => browse.prompt = Prompt::None,
            Prompt::Delete { .. } => match key.code {
                KeyCode::Enter => browse.confirm_delete(),
                KeyCode::Esc => browse.prompt = Prompt::None,
                _ => {}
            },
            Prompt::Line { .. } => match key.code {
                KeyCode::Esc => browse.prompt = Prompt::None,
                KeyCode::Backspace => browse.pop(),
                KeyCode::Char(ch) => browse.push(ch),
                KeyCode::Enter => browse.submit_line(),
                _ => {}
            },
            Prompt::SshForm(_) => match key.code {
                KeyCode::Esc => browse.dismiss_form(),
                KeyCode::Backspace => browse.form_pop(),
                KeyCode::Char(ch) => browse.form_push(ch),
                KeyCode::Enter => browse.submit_ssh_form(),
                _ => {}
            },
            Prompt::HostEdit(_) | Prompt::PageForm(_) => browse.drive_form(key),
            Prompt::Host(_) | Prompt::None | Prompt::GetReview(_) => {}
        }
        Apply::Stay
    }

    fn drive_files(&mut self, key: KeyEvent) -> Apply {
        let action = {
            let Screen::Browse(browse) = &mut self.screen else {
                return Apply::Stay;
            };
            let count = browse.entries.len();
            match key.code {
                KeyCode::Char('q') => Apply::Quit,
                KeyCode::Esc => Apply::Disks,
                KeyCode::Down | KeyCode::Char('j') if count > 0 => {
                    browse.selected = (browse.selected + 1) % count;
                    Apply::Stay
                }
                KeyCode::Up | KeyCode::Char('k') if count > 0 => {
                    browse.selected = (browse.selected + count - 1) % count;
                    Apply::Stay
                }
                KeyCode::PageDown if count > 0 => {
                    browse.selected = (browse.selected + 10).min(count - 1);
                    Apply::Stay
                }
                KeyCode::PageUp => {
                    browse.selected = browse.selected.saturating_sub(10);
                    Apply::Stay
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    browse.open_dir();
                    Apply::Stay
                }
                KeyCode::Enter => Apply::Stay,
                KeyCode::Char(' ') if key.kind != KeyEventKind::Repeat => {
                    browse.toggle_mark();
                    Apply::Stay
                }
                KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('u') => {
                    browse.go_up();
                    Apply::Stay
                }
                KeyCode::Char('r') => {
                    browse.reload();
                    Apply::Stay
                }
                KeyCode::Char('n') => {
                    browse.prompt = Prompt::Line {
                        title: "directory name",
                        value: String::new(),
                    };
                    Apply::Stay
                }
                KeyCode::Char('p') => {
                    browse.open_host_browser();
                    Apply::Stay
                }
                KeyCode::Char('g') => {
                    browse.start_get();
                    Apply::Stay
                }
                KeyCode::Char('b') if key.kind != KeyEventKind::Repeat => {
                    browse.begin_health();
                    Apply::Stay
                }
                KeyCode::Char('w') if key.kind != KeyEventKind::Repeat => {
                    browse.prompt = Prompt::Line {
                        title: "backup path",
                        value: String::new(),
                    };
                    Apply::Stay
                }
                KeyCode::Char('d') | KeyCode::Delete => {
                    browse.start_delete();
                    Apply::Stay
                }
                KeyCode::Char('i') => {
                    browse.show_selected_stat();
                    Apply::Stay
                }
                KeyCode::Char('v') => {
                    browse.show_volume_stat();
                    Apply::Stay
                }
                KeyCode::Char('?') => {
                    browse.prompt = Prompt::Note {
                        title: "keys".into(),
                        body: BROWSE_HELP.into(),
                    };
                    Apply::Stay
                }
                KeyCode::Char('/') => {
                    browse.begin_find();
                    Apply::Stay
                }
                _ => Apply::Stay,
            }
        };
        action
    }

    fn drive_ssh(&mut self, key: KeyEvent) -> Apply {
        let action = {
            let Screen::Browse(browse) = &mut self.screen else {
                return Apply::Stay;
            };
            let count = browse.ssh_len();
            match key.code {
                KeyCode::Char('q') => Apply::Quit,
                KeyCode::Esc => Apply::Disks,
                KeyCode::Down | KeyCode::Char('j') if count > 0 => {
                    browse.ssh.selected = (browse.ssh.selected + 1) % count;
                    Apply::Stay
                }
                KeyCode::Up | KeyCode::Char('k') if count > 0 => {
                    browse.ssh.selected = (browse.ssh.selected + count - 1) % count;
                    Apply::Stay
                }
                KeyCode::PageDown if count > 0 => {
                    browse.ssh.selected = (browse.ssh.selected + 10).min(count - 1);
                    Apply::Stay
                }
                KeyCode::PageUp => {
                    browse.ssh.selected = browse.ssh.selected.saturating_sub(10);
                    Apply::Stay
                }
                KeyCode::Enter => match browse.ssh.pane {
                    SshPane::Hosts => match browse.selected_host_tag() {
                        Some(tag) => Apply::Connect(tag),
                        None => {
                            browse.note_ssh("nothing selected".into());
                            Apply::Stay
                        }
                    },
                    SshPane::Keys => {
                        browse.show_selected_key();
                        Apply::Stay
                    }
                    SshPane::Passwords => {
                        browse.copy_selected_password();
                        Apply::Stay
                    }
                },
                KeyCode::Char('i') => {
                    match browse.ssh.pane {
                        SshPane::Hosts => browse.show_selected_host(),
                        SshPane::Keys => browse.show_selected_key(),
                        SshPane::Passwords => browse.show_selected_password(),
                    }
                    Apply::Stay
                }
                KeyCode::Char('e') if browse.ssh.pane == SshPane::Hosts => {
                    browse.begin_ssh_edit();
                    Apply::Stay
                }
                KeyCode::Char('n') => {
                    browse.begin_ssh_new();
                    Apply::Stay
                }
                KeyCode::Char('a') if browse.ssh.pane == SshPane::Keys => {
                    browse.begin_ssh_add();
                    Apply::Stay
                }
                KeyCode::Char('g') if browse.ssh.pane == SshPane::Keys => {
                    browse.begin_public_download();
                    Apply::Stay
                }
                KeyCode::Char('g') if browse.ssh.pane == SshPane::Passwords => {
                    browse.begin_password_generate();
                    Apply::Stay
                }
                KeyCode::Char('c') if browse.ssh.pane == SshPane::Passwords => {
                    browse.copy_selected_password();
                    Apply::Stay
                }
                KeyCode::Char('d') => {
                    browse.begin_ssh_delete();
                    Apply::Stay
                }
                _ => Apply::Stay,
            }
        };
        if matches!(
            key.code,
            KeyCode::Char('n')
                | KeyCode::Char('e')
                | KeyCode::Char('a')
                | KeyCode::Char('g')
                | KeyCode::Char('c')
                | KeyCode::Char('d')
                | KeyCode::Char('i')
                | KeyCode::Enter
        ) {
            self.ignore_repeat = Some(key.code);
        }
        action
    }

    fn enter_hosts(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.view = BrowseView::Hosts;
        browse.ssh.pane = SshPane::Hosts;
        browse.ssh.selected = 0;
        browse.menu.open = false;
        browse.reload_ssh();
    }

    fn enter_keys(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.view = BrowseView::Keys;
        browse.ssh.pane = SshPane::Keys;
        browse.ssh.selected = 0;
        browse.menu.open = false;
        browse.reload_ssh();
    }

    fn enter_passwords(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.view = BrowseView::Passwords;
        browse.ssh.pane = SshPane::Passwords;
        browse.ssh.selected = 0;
        browse.menu.open = false;
        browse.reload_ssh();
    }

    fn enter_files(&mut self) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.view = BrowseView::Files;
        browse.menu.open = false;
        browse.reload();
    }

    fn arm_connect(&mut self, tag: String) {
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        let detail = tag.clone();
        browse.offload(
            "Connecting",
            detail,
            move |browse| match crate::ssh::load_session(browse.vol(), &tag) {
                Ok(session) => {
                    browse.armed_session = Some(ArmedConnect { tag, session });
                }
                Err(err) => browse.note_ssh(err.to_string()),
            },
        );
    }

    fn on_volume_find(&mut self, key: KeyEvent) -> Result<bool> {
        let settle = {
            let Screen::Browse(browse) = &mut self.screen else {
                return Ok(false);
            };
            if matches!(
                key.code,
                KeyCode::Char(_)
                    | KeyCode::Backspace
                    | KeyCode::Up
                    | KeyCode::Down
                    | KeyCode::Left
                    | KeyCode::Right
                    | KeyCode::PageUp
                    | KeyCode::PageDown
            ) {
                browse.find_after = None;
            }
            match key.code {
                KeyCode::Esc if browse.find_walk.is_some() => {
                    browse.find_list_at = None;
                    browse.find_after = Some(FindThen::Cancel);
                    None
                }
                KeyCode::Esc => {
                    browse.end_find(true);
                    None
                }
                KeyCode::Enter if browse.find_pending() => Some(FindThen::Close),
                KeyCode::Enter => {
                    browse.end_find(false);
                    None
                }
                KeyCode::Backspace => {
                    browse.find_pop();
                    None
                }
                KeyCode::BackTab if browse.find_pending() => Some(FindThen::Tab(-1)),
                KeyCode::BackTab => {
                    browse.complete_tab(-1);
                    None
                }
                KeyCode::Tab
                    if key.modifiers.contains(KeyModifiers::SHIFT) && browse.find_pending() =>
                {
                    Some(FindThen::Tab(-1))
                }
                KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
                    browse.complete_tab(-1);
                    None
                }
                KeyCode::Tab if browse.find_pending() => Some(FindThen::Tab(1)),
                KeyCode::Tab => {
                    browse.complete_tab(1);
                    None
                }
                KeyCode::Char(ch) => {
                    browse.find_push(ch);
                    None
                }
                KeyCode::Down | KeyCode::Right => {
                    browse.move_shown(1);
                    None
                }
                KeyCode::Up | KeyCode::Left => {
                    browse.move_shown(-1);
                    None
                }
                KeyCode::PageDown => {
                    browse.move_shown(10);
                    None
                }
                KeyCode::PageUp => {
                    browse.move_shown(-10);
                    None
                }
                _ => None,
            }
        };
        if let Some(then) = settle {
            self.settle_volume_find(then);
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
                        let cwd = browse.cwd.clone();
                        browse.offload("Opening", cwd, move |browse| {
                            browse.prompt = Prompt::Host(HostBrowser::start_get(files));
                        });
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
                KeyCode::Enter => browse.confirm_delete(),
                KeyCode::Esc => browse.prompt = Prompt::None,
                _ => {}
            },
            Prompt::Line { .. } => match key.code {
                KeyCode::Esc => browse.prompt = Prompt::None,
                KeyCode::Backspace => browse.pop(),
                KeyCode::Char(ch) => browse.push(ch),
                KeyCode::Enter => browse.submit_line(),
                _ => {}
            },
            Prompt::SshForm(_) => match key.code {
                KeyCode::Esc => browse.dismiss_form(),
                KeyCode::Backspace => browse.form_pop(),
                KeyCode::Char(ch) => browse.form_push(ch),
                KeyCode::Enter => browse.submit_ssh_form(),
                _ => {}
            },
            Prompt::HostEdit(_) | Prompt::PageForm(_) => browse.drive_form(key),
            Prompt::Host(_) | Prompt::None | Prompt::GetReview(_) => {}
        }
        self.take_browse_notice();
        Ok(false)
    }

    fn on_host_key(&mut self, key: KeyEvent, _terminal: &mut Term) -> Result<bool> {
        let command = {
            let Screen::Browse(browse) = &mut self.screen else {
                return Ok(false);
            };
            let finding = matches!(
                &browse.prompt,
                Prompt::Host(host) if host.confirm.is_none() && host.find.is_some()
            );
            if finding {
                if matches!(
                    key.code,
                    KeyCode::Char(_)
                        | KeyCode::Backspace
                        | KeyCode::Up
                        | KeyCode::Down
                        | KeyCode::Left
                        | KeyCode::Right
                        | KeyCode::PageUp
                        | KeyCode::PageDown
                ) {
                    browse.find_after = None;
                }
                match key.code {
                    KeyCode::Esc if browse.find_walk.is_some() => {
                        browse.find_list_at = None;
                        browse.find_after = Some(FindThen::Cancel);
                        HostCmd::Stay
                    }
                    KeyCode::Esc => {
                        browse.find_list_at = None;
                        HostCmd::FindEnd(true)
                    }
                    KeyCode::Enter if browse.find_pending() => HostCmd::FindApply(FindThen::Close),
                    KeyCode::Enter => HostCmd::FindEnd(false),
                    KeyCode::Backspace => {
                        browse.queue_host_find_pop();
                        HostCmd::Stay
                    }
                    KeyCode::BackTab if browse.find_pending() => {
                        HostCmd::FindApply(FindThen::Tab(-1))
                    }
                    KeyCode::BackTab => {
                        if let Prompt::Host(host) = &mut browse.prompt {
                            host.complete_tab(-1);
                        }
                        HostCmd::Stay
                    }
                    KeyCode::Tab
                        if key.modifiers.contains(KeyModifiers::SHIFT) && browse.find_pending() =>
                    {
                        HostCmd::FindApply(FindThen::Tab(-1))
                    }
                    KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
                        if let Prompt::Host(host) = &mut browse.prompt {
                            host.complete_tab(-1);
                        }
                        HostCmd::Stay
                    }
                    KeyCode::Tab if browse.find_pending() => HostCmd::FindApply(FindThen::Tab(1)),
                    KeyCode::Tab => {
                        if let Prompt::Host(host) = &mut browse.prompt {
                            host.complete_tab(1);
                        }
                        HostCmd::Stay
                    }
                    KeyCode::Char(ch) => {
                        browse.queue_host_find_char(ch);
                        HostCmd::Stay
                    }
                    KeyCode::Down | KeyCode::Right => {
                        if let Prompt::Host(host) = &mut browse.prompt {
                            host.move_shown(1);
                        }
                        HostCmd::Stay
                    }
                    KeyCode::Up | KeyCode::Left => {
                        if let Prompt::Host(host) = &mut browse.prompt {
                            host.move_shown(-1);
                        }
                        HostCmd::Stay
                    }
                    KeyCode::PageDown => {
                        if let Prompt::Host(host) = &mut browse.prompt {
                            host.move_shown(10);
                        }
                        HostCmd::Stay
                    }
                    KeyCode::PageUp => {
                        if let Prompt::Host(host) = &mut browse.prompt {
                            host.move_shown(-10);
                        }
                        HostCmd::Stay
                    }
                    _ => HostCmd::Stay,
                }
            } else {
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
                        KeyCode::Right | KeyCode::Char('l') => HostCmd::OpenDir,
                        KeyCode::Enter => match host.job {
                            HostJob::Put => HostCmd::Put,
                            HostJob::Get => HostCmd::ConfirmGet,
                        },
                        KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => HostCmd::UpDir,
                        KeyCode::Char(' ') if host.job == HostJob::Get => HostCmd::Stay,
                        KeyCode::Char(' ') if key.kind != KeyEventKind::Repeat => {
                            match host.toggle_selected() {
                                Ok(()) => HostCmd::Stay,
                                Err(err) => HostCmd::Note(err),
                            }
                        }
                        KeyCode::Char('r') => HostCmd::ReloadDir,
                        KeyCode::Char('~') => HostCmd::Home,
                        KeyCode::Char('/') => {
                            host.begin_find();
                            HostCmd::Stay
                        }
                        _ => HostCmd::Stay,
                    }
                }
            }
        };
        match command {
            HostCmd::Stay => {}
            HostCmd::Close => self.close_host(),
            HostCmd::Quit => return Ok(true),
            HostCmd::Note(text) => self.note(true, text),
            HostCmd::Put => self.put_marked()?,
            HostCmd::ConfirmGet => self.ask_get_dest(),
            HostCmd::GetHere => self.begin_get()?,
            HostCmd::OpenDir => self.offload_host("Opening", |browse| {
                if let Prompt::Host(host) = &mut browse.prompt {
                    host.open_selected();
                }
            }),
            HostCmd::UpDir => self.offload_host("Opening", |browse| {
                if let Prompt::Host(host) = &mut browse.prompt {
                    host.go_up();
                }
            }),
            HostCmd::ReloadDir => self.offload_host("Opening", |browse| {
                if let Prompt::Host(host) = &mut browse.prompt {
                    host.reload();
                }
            }),
            HostCmd::Home => self.offload_host("Opening", |browse| {
                if let Prompt::Host(host) = &mut browse.prompt {
                    match user_home() {
                        Some(path) => host.jump(path),
                        None => host.error = "home directory is not available".into(),
                    }
                }
            }),
            HostCmd::FindApply(then) => self.settle_host_find(then),
            HostCmd::FindEnd(cancel) => self.offload_host("Finding", move |browse| {
                if let Prompt::Host(host) = &mut browse.prompt {
                    host.end_find(cancel);
                }
            }),
        }
        self.take_browse_notice();
        Ok(false)
    }

    fn offload_host<F>(&mut self, title: &str, work: F)
    where
        F: FnOnce(&mut Browse) + Send + 'static,
    {
        let detail = match &self.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Host(host) => host.cwd.display().to_string(),
                _ => browse.cwd.clone(),
            },
            _ => String::new(),
        };
        let Screen::Browse(browse) = &mut self.screen else {
            return;
        };
        browse.offload(title, detail, work);
    }

    fn put_marked(&mut self) -> Result<()> {
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
        let watch = InitWatch::new();
        let watch_worker = Arc::clone(&watch);
        let cancel = Arc::new(AtomicU8::new(0));
        let cancel_worker = Arc::clone(&cancel);
        let Screen::Browse(browse) = &mut self.screen else {
            return Ok(());
        };
        browse.offload_paint(
            "Copy",
            volume_cwd.clone(),
            Some(Arc::clone(&watch)),
            cancel,
            Paint::Copy,
            move |browse| perform_put(browse, &volume_cwd, &marked, &watch_worker, &cancel_worker),
        );
        Ok(())
    }

    fn ask_get_dest(&mut self) {
        self.offload_host("Opening", |browse| {
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
        });
    }

    fn begin_get(&mut self) -> Result<()> {
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
        if files.is_empty() {
            self.fail_host("select a file".into());
            return Ok(());
        }
        let items: Vec<GetItem> = files
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
        let paint = Arc::new(Mutex::new(GetPaint {
            items,
            dest: dest_dir.clone(),
        }));
        let paint_worker = Arc::clone(&paint);
        let cancel = Arc::new(AtomicU8::new(0));
        let cancel_worker = Arc::clone(&cancel);
        let Screen::Browse(browse) = &mut self.screen else {
            return Ok(());
        };
        browse.offload_paint(
            "Get",
            dest_dir.display().to_string(),
            None,
            cancel,
            Paint::Get(paint),
            move |browse| perform_get(browse, dest_dir, paint_worker, cancel_worker),
        );
        Ok(())
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

    fn hold_frame(&self) -> bool {
        matches!(self.screen, Screen::Parked) && self.job_is_quiet()
    }

    fn job_is_quiet(&self) -> bool {
        self.job
            .as_ref()
            .is_some_and(|job| job.started.elapsed() < JOB_CURTAIN)
    }

    fn loader_view(&self) -> Option<LoaderView> {
        if let Some(dial) = &self.dial {
            return Some(LoaderView {
                title: "Connecting".into(),
                detail: dial.tag.clone(),
                elapsed: dial.started.elapsed(),
            });
        }
        let job = self.job.as_ref()?;
        if self.job_is_quiet() || !matches!(job.paint, Paint::Plain) {
            return None;
        }
        Some(LoaderView {
            title: job.title.clone(),
            detail: job.detail.clone(),
            elapsed: job.started.elapsed(),
        })
    }

    fn draw(&self, frame: &mut Frame) {
        self.render(frame);
        *self.last_frame.borrow_mut() = Some(frame.buffer_mut().clone());
    }

    fn render(&self, frame: &mut Frame) {
        if let Some(job) = &self.job {
            if !self.job_is_quiet() && !matches!(job.paint, Paint::Plain) {
                self.draw_job(frame, job);
                return;
            }
        }
        let loader = self.loader_view();
        if let Some(loader) = loader.as_ref() {
            if matches!(self.screen, Screen::Parked) {
                self.paint_held_loader(frame, loader);
                self.draw_alert(frame);
                return;
            }
        }
        if loader.is_none() {
            if let Screen::Browse(browse) = &self.screen {
                if let Some(overlay) = &browse.overlay {
                    match overlay {
                        Overlay::Health(view) => draw_health(frame, view, false),
                        Overlay::Get { items, dest } => {
                            draw_get_progress(frame, items, dest, false)
                        }
                    }
                    self.draw_alert(frame);
                    return;
                }
            }
        }
        self.draw_screen(frame, loader.as_ref());
    }

    fn draw_screen(&self, frame: &mut Frame, loader: Option<&LoaderView>) {
        paint_screen(frame);
        let constraints: &[Constraint] = if loader.is_some() {
            &[
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ]
        } else {
            &[Constraint::Length(1), Constraint::Min(0)]
        };
        let chunks = Layout::vertical(constraints).split(frame.area());
        let header = chunks[0];
        let body = chunks[1];
        if let Screen::Browse(browse) = &self.screen {
            if browse.shows_menu() {
                paint_menu(frame, header, browse.menu.open, &self.detail());
            } else {
                paint_banner(frame, header, self.section(), &self.detail());
            }
        } else {
            paint_banner(frame, header, self.section(), &self.detail());
        }
        match &self.screen {
            Screen::Pick(pick) => draw_pick(frame, body, pick),
            Screen::Sudo(sudo) => {
                let inner = framed(frame, body);
                draw_secret(
                    frame,
                    inner,
                    "Grant access",
                    &format!(
                        "sudo password to allow {} to open {}",
                        super::user_name(),
                        sudo.path.display()
                    ),
                    &sudo.password.bullets(),
                );
            }
            Screen::Unlock(unlock) => {
                let inner = framed(frame, body);
                draw_secret(
                    frame,
                    inner,
                    "Unlock",
                    &format!("{} is an HDNFS volume", unlock.path.display()),
                    &unlock.password.bullets(),
                );
            }
            Screen::Setup(setup) => draw_setup(frame, body, setup),
            Screen::Passwd(form) => draw_passwd(frame, body, form),
            Screen::Browse(browse) => {
                draw_browse(frame, body, browse);
                if browse.menu.open && browse.shows_menu() {
                    draw_menu_dropdown(frame, browse.menu.cursor);
                }
            }
            Screen::Parked => {
                frame.render_widget(Paragraph::new("Working").style(surface()), body);
            }
        }
        if body.height > 0 && body.width > 0 {
            paint_edge_row(frame, body.x, body.y + body.height - 1, body.width);
            let help_line = if self.alert.is_some() {
                keymap(&[("any key", "close")])
            } else if loader.is_some() {
                cancel_keymap()
            } else {
                self.help_line()
            };
            paint_shortcuts(frame, body, help_line);
        }
        if let Some(loader) = loader {
            draw_loader_bar(frame, chunks[2], loader);
        }
        self.draw_alert(frame);
    }

    /// The volume is on the worker, so the last frame stays. The content border
    /// keeps the cancel keys, and the loader is the row under that border.
    fn paint_held_loader(&self, frame: &mut Frame, loader: &LoaderView) {
        let area = frame.area();
        let saved = self.last_frame.borrow().clone();
        let restored = match saved {
            Some(saved) if saved.area == area => {
                frame.buffer_mut().content.clone_from(&saved.content);
                true
            }
            _ => false,
        };
        if !restored {
            paint_screen(frame);
        }
        if area.height < 2 || area.width == 0 {
            return;
        }
        let content = Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: area.height - 1,
        };
        paint_edge_row(
            frame,
            content.x,
            content.y + content.height - 1,
            content.width,
        );
        paint_shortcuts(frame, content, cancel_keymap());
        let bar = Rect {
            x: area.x,
            y: area.bottom() - 1,
            width: area.width,
            height: 1,
        };
        draw_loader_bar(frame, bar, loader);
    }

    fn draw_alert(&self, frame: &mut Frame) {
        let Some(alert) = &self.alert else {
            return;
        };
        draw_note(frame, frame.area(), "Notice", alert);
    }

    fn draw_job(&self, frame: &mut Frame, job: &Job) {
        match &job.paint {
            Paint::Get(paint) => {
                let snap = paint.lock().unwrap_or_else(|err| err.into_inner()).clone();
                draw_get_progress(frame, &snap.items, &snap.dest, true);
            }
            Paint::Health => {
                let (stage, done, total) = job
                    .watch
                    .as_ref()
                    .map(|watch| watch.snapshot())
                    .unwrap_or_else(|| (String::new(), 0, 0));
                draw_health(
                    frame,
                    &HealthView {
                        stage: if stage.is_empty() {
                            "starting".into()
                        } else {
                            stage
                        },
                        done,
                        total: total.max(1),
                        report: None,
                        error: None,
                    },
                    true,
                );
            }
            Paint::Backup => {
                let (_, done, total) = job
                    .watch
                    .as_ref()
                    .map(|watch| watch.snapshot())
                    .unwrap_or_else(|| (String::new(), 0, 0));
                draw_backup_progress(frame, &job.detail, done, total);
            }
            Paint::Init | Paint::Copy => {
                let (stage, done, total) = job
                    .watch
                    .as_ref()
                    .map(|watch| watch.snapshot())
                    .unwrap_or_else(|| (String::new(), 0, 0));
                let stage = if stage.is_empty() { "starting" } else { &stage };
                draw_init_progress(frame, &job.detail, stage, done, total);
            }
            Paint::Plain => {}
        }
    }

    fn section(&self) -> &'static str {
        match &self.screen {
            Screen::Pick(_) => "Disks",
            Screen::Sudo(_) => "Access",
            Screen::Unlock(_) => "Unlock",
            Screen::Setup(_) => "Initialize",
            Screen::Passwd(_) => "Password",
            Screen::Parked => "Working",
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
            Screen::Parked => String::new(),
            Screen::Pick(pick) => pick_summary(&pick.disks),
            Screen::Sudo(sudo) => sudo.path.display().to_string(),
            Screen::Unlock(unlock) => unlock.path.display().to_string(),
            Screen::Setup(setup) => setup.path.display().to_string(),
            Screen::Passwd(form) => form.path.display().to_string(),
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Host(host) if host.job == HostJob::Get => host.cwd.display().to_string(),
                Prompt::Host(_) => format!("into {}", browse.cwd),
                Prompt::GetReview(_) => browse.cwd.clone(),
                _ => browse.volume_path.display().to_string(),
            },
        }
    }

    fn help_line(&self) -> Line<'static> {
        if self.alert.is_some() {
            return keymap(&[("any key", "close")]);
        }
        match &self.screen {
            Screen::Browse(browse) if browse.menu.open && browse.shows_menu() => keymap(&[
                ("j k", "move"),
                ("enter", "open"),
                ("esc", "close"),
                ("m", "close"),
            ]),
            Screen::Parked => keymap(&[("esc", "cancel"), ("q", "cancel"), ("ctrl-c", "cancel")]),
            Screen::Pick(pick) if pick.editing => keymap(&[("enter", "open"), ("esc", "cancel")]),
            Screen::Pick(_) => keymap_gap(
                &[
                    ("j k", "move"),
                    ("enter", "open"),
                    ("i", "init"),
                    ("n", "new"),
                    ("c", "passwd"),
                    ("/", "path"),
                    ("r", "refresh"),
                    ("q", "quit"),
                ],
                2,
            ),
            Screen::Sudo(_) | Screen::Unlock(_) => {
                keymap(&[("enter", "continue"), ("esc", "disks")])
            }
            Screen::Setup(_) => {
                keymap(&[("tab", "next"), ("enter", "initialize"), ("esc", "disks")])
            }
            Screen::Passwd(_) => keymap(&[("tab", "next"), ("enter", "change"), ("esc", "disks")]),
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
                Prompt::None if browse.view == BrowseView::Hosts => keymap(&[
                    ("j k", "move"),
                    ("enter", "connect"),
                    ("i", "info"),
                    ("e", "edit"),
                    ("n", "new"),
                    ("d", "delete"),
                    ("m", "menu"),
                    ("esc", "disks"),
                    ("q", "quit"),
                ]),
                Prompt::None if browse.view == BrowseView::Keys => keymap_gap(
                    &[
                        ("j k", "move"),
                        ("enter", "info"),
                        ("g", "public"),
                        ("n", "new"),
                        ("a", "add"),
                        ("d", "delete"),
                        ("m", "menu"),
                        ("esc", "disks"),
                        ("q", "quit"),
                    ],
                    2,
                ),
                Prompt::None if browse.view == BrowseView::Passwords => keymap_gap(
                    &[
                        ("j k", "move"),
                        ("c", "copy"),
                        ("n", "new"),
                        ("g", "generate"),
                        ("d", "delete"),
                        ("m", "menu"),
                        ("esc", "disks"),
                        ("q", "quit"),
                    ],
                    2,
                ),
                Prompt::None => keymap_gap(
                    &[
                        ("m", "menu"),
                        ("h", "back"),
                        ("j k", "move"),
                        ("l", "open"),
                        ("/", "find"),
                        ("space", "select"),
                        ("g", "get"),
                        ("p", "put"),
                        ("d", "delete"),
                        ("b", "health"),
                        ("w", "backup"),
                        ("q", "quit"),
                    ],
                    2,
                ),
                Prompt::Delete { .. } => keymap(&[("enter", "confirm"), ("esc", "cancel")]),
                Prompt::Note { .. } => keymap(&[("any key", "close")]),
                Prompt::HostEdit(_) | Prompt::PageForm(_) => keymap(&[
                    ("up down", "move"),
                    ("tab", "next"),
                    ("enter", "save"),
                    ("esc", "cancel"),
                ]),
                Prompt::Line { .. } | Prompt::SshForm(_) => {
                    keymap(&[("enter", "confirm"), ("esc", "cancel")])
                }
            },
        }
    }
}

const INK: Color = Color::Rgb(0, 0, 0);
const RAISED: Color = Color::Rgb(0, 0, 0);
const LINE: Color = Color::Rgb(80, 80, 80);
const TEXT: Color = Color::Rgb(236, 238, 244);
const MUTED: Color = Color::Rgb(160, 160, 160);
const SAGE: Color = Color::Rgb(125, 201, 173);
const SAGE_INK: Color = Color::Rgb(0, 0, 0);
const BAD: Color = Color::Rgb(232, 140, 140);
const BAD_BG: Color = Color::Rgb(0, 0, 0);
const ACCENT: Color = SAGE;
const TRACK: Color = Color::Rgb(36, 36, 36);

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

fn framed(frame: &mut Frame, area: Rect) -> Rect {
    let block = shell("", surface());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    inner
}

fn paint_screen(frame: &mut Frame) {
    frame.render_widget(Block::default().style(surface()), frame.area());
}

fn paint_menu(frame: &mut Frame, area: Rect, open: bool, detail: &str) {
    if area.is_empty() {
        return;
    }
    frame.render_widget(
        Paragraph::new(menu_banner_line(area.width, open, detail)).style(raised()),
        area,
    );
}

fn menu_banner_line(width: u16, open: bool, detail: &str) -> Line<'static> {
    let brand = Span::styled(" HDNFS", fg(SAGE).add_modifier(Modifier::BOLD));
    let lead = Span::raw("   ");
    let menu_style = if open {
        highlight().add_modifier(Modifier::BOLD)
    } else {
        fg(SAGE).add_modifier(Modifier::BOLD)
    };
    let menu = Span::styled(" menu ", menu_style);
    let left = brand.width() + lead.width() + menu.width();
    let mut spans = vec![brand, lead, menu];
    let width = width as usize;
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

fn draw_menu_dropdown(frame: &mut Frame, cursor: usize) {
    let frame_area = frame.area();
    let mut area = Rect {
        x: 9,
        y: 1,
        width: 12,
        height: MENU_LABELS.len() as u16,
    };
    if area.x >= frame_area.right() || area.y >= frame_area.bottom() {
        return;
    }
    area.width = area.width.min(frame_area.right() - area.x);
    area.height = area.height.min(frame_area.bottom() - area.y);
    if area.width < 6 || area.height < 1 {
        return;
    }
    frame.render_widget(Clear, area);
    frame.render_widget(Block::default().style(surface()), area);
    for (index, name) in MENU_LABELS.into_iter().enumerate() {
        if index as u16 >= area.height {
            break;
        }
        let row = Rect {
            x: area.x,
            y: area.y + index as u16,
            width: area.width,
            height: 1,
        };
        let style = if index == cursor {
            highlight()
        } else {
            surface()
        };
        frame.render_widget(Paragraph::new(format!(" {name}")).style(style), row);
    }
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

/// Keep the end of `text`. Paths differ at the end, so that is the part to show.
fn fit_tail(text: &str, width: usize) -> String {
    if width == 0 || text.is_empty() {
        return String::new();
    }
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    let mut out = String::from("…");
    out.extend(text.chars().skip(count - (width - 1)));
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
    keymap_gap(pairs, 4)
}

fn keymap_gap(pairs: &[(&str, &str)], gap: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    let sep = " ".repeat(gap);
    for (index, (key, label)) in pairs.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw(sep.clone()));
        }
        spans.push(Span::styled((*key).to_string(), fg(SAGE)));
        spans.push(Span::styled(format!(" {label}"), fg(MUTED)));
    }
    Line::from(spans)
}

fn paint_edge_row(frame: &mut Frame, x: u16, y: u16, width: u16) {
    if width == 0 {
        return;
    }
    let style = fg(LINE).bg(INK);
    let buf = frame.buffer_mut();
    if width == 1 {
        buf.set_string(x, y, "╰", style);
        return;
    }
    buf.set_string(x, y, "╰", style);
    buf.set_string(x + 1, y, &"─".repeat((width - 2) as usize), style);
    buf.set_string(x + width - 1, y, "╯", style);
}

fn paint_shortcuts(frame: &mut Frame, area: Rect, line: Line<'_>) {
    if area.height == 0 || area.width < 3 {
        return;
    }
    let room = (area.width - 2) as usize;
    let text_width = line.width().min(room) as u16;
    if text_width == 0 {
        return;
    }
    let rect = Rect {
        x: area.x + 1,
        y: area.y + area.height - 1,
        width: text_width,
        height: 1,
    };
    frame.render_widget(Paragraph::new(line).style(surface()), rect);
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
                "No disks or volumes here. Press n for a new file, or / to type a path.",
                fg(MUTED),
            ))
            .block(panel("Devices"))
            .style(surface()),
            area,
        );
    } else {
        let block = panel("Devices");
        let widths = disk_widths(&pick.disks, block.inner(area).width as usize);
        let items: Vec<ListItem> = pick
            .disks
            .iter()
            .map(|disk| ListItem::new(disk_row(disk, &widths)))
            .collect();
        let list = List::new(items)
            .block(block)
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
            .block(shell(format!(" {title} "), surface()))
            .style(surface())
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_passwd(frame: &mut Frame, area: Rect, form: &PasswdForm) {
    let mut lines = vec![
        Line::from(Span::styled(
            "The new password re-wraps the volume key. Files already stored stay as they are.",
            fg(MUTED),
        )),
        Line::from(""),
        labeled("Path", &form.path.display().to_string()),
        Line::from(""),
    ];
    let fields = [
        ("Current", form.current.bullets()),
        ("New", form.next.bullets()),
        ("Again", form.again.bullets()),
    ];
    for (index, (label, value)) in fields.into_iter().enumerate() {
        lines.push(editor_field_line(label, &value, index == form.cursor));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel("Change password"))
            .style(surface())
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_setup(frame: &mut Frame, area: Rect, setup: &Setup) {
    let intro = if setup.fields.contains(&FieldId::Path) && !setup.block {
        "Type the file path. Choose a size, for example 64M. The password you set here unlocks the volume."
    } else if setup.block {
        "Retype the path to confirm. A smaller size uses a prefix and leaves the rest untouched."
    } else {
        "Choose a size, for example 64M. The password you set here unlocks the volume."
    };
    let mut lines = vec![Line::from(Span::styled(intro, fg(MUTED))), Line::from("")];
    if !setup.fields.contains(&FieldId::Path) {
        lines.push(labeled("Path", &setup.path.display().to_string()));
    }
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

fn draw_host_editor(frame: &mut Frame, area: Rect, editor: &HostEditor) {
    let title = if editor.create {
        "New host".to_string()
    } else {
        format!("Edit {}", editor.tag)
    };
    draw_form_page(frame, area, &title, |width| {
        host_editor_lines(editor, width)
    });
}

fn draw_page_form(frame: &mut Frame, area: Rect, form: &PageForm) {
    draw_form_page(frame, area, form.title, |width| {
        page_form_lines(form, width)
    });
}

fn draw_form_page(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines_for: impl FnOnce(usize) -> (Vec<Line<'static>>, usize),
) {
    let block = panel(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let (lines, active) = lines_for(inner.width as usize);
    let height = inner.height as usize;
    let start = if lines.len() <= height {
        0
    } else {
        active
            .saturating_sub(height.saturating_sub(1))
            .min(lines.len() - height)
    };
    let visible: Vec<Line<'static>> = lines.into_iter().skip(start).take(height).collect();
    frame.render_widget(Paragraph::new(visible).style(surface()), inner);
}

fn host_editor_lines(editor: &HostEditor, width: usize) -> (Vec<Line<'static>>, usize) {
    let mut lines = Vec::new();
    if !editor.error.is_empty() {
        lines.push(Line::from(Span::styled(fit(&editor.error, width), fg(BAD))));
        lines.push(Line::from(""));
    }
    if editor.create {
        lines.push(Line::from(Span::styled(
            fit("An empty user, port, or timeout is left unset.", width),
            fg(MUTED),
        )));
        lines.push(Line::from(""));
    } else {
        lines.push(labeled("tag", &editor.tag));
    }
    let active = lines.len() + editor.cursor;
    for (index, (label, value)) in editor.fields().into_iter().enumerate() {
        lines.push(editor_field_line(label, &value, index == editor.cursor));
    }
    (lines, active)
}

fn editor_field_line(label: &str, value: &str, active: bool) -> Line<'static> {
    let marker = if active {
        Span::styled("▸  ", fg(SAGE).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("   ", fg(MUTED))
    };
    // A line that is only a normal space is placed on the following row.
    let value_span = if active {
        let cursor = if value.is_empty() { "\u{00a0}" } else { " " };
        Span::styled(format!("{value}{cursor}"), highlight())
    } else {
        Span::styled(value.to_string(), fg(TEXT))
    };
    Line::from(vec![
        marker,
        Span::styled(
            format!("{label:<14}"),
            if active { fg(SAGE) } else { fg(MUTED) },
        ),
        value_span,
    ])
}

fn page_form_lines(form: &PageForm, width: usize) -> (Vec<Line<'static>>, usize) {
    let mut lines = Vec::new();
    if !form.error.is_empty() {
        lines.push(Line::from(Span::styled(fit(&form.error, width), fg(BAD))));
        lines.push(Line::from(""));
    }
    if !form.hint.is_empty() {
        lines.push(Line::from(Span::styled(fit(form.hint, width), fg(MUTED))));
        lines.push(Line::from(""));
    }
    let active = lines.len() + form.cursor;
    for (index, field) in form.fields.iter().enumerate() {
        lines.push(editor_field_line(
            field.label,
            &field.shown(),
            index == form.cursor,
        ));
    }
    (lines, active)
}

fn draw_browse(frame: &mut Frame, area: Rect, browse: &Browse) {
    if let Prompt::HostEdit(editor) = &browse.prompt {
        draw_host_editor(frame, area, editor);
        return;
    }
    if let Prompt::PageForm(form) = &browse.prompt {
        draw_page_form(frame, area, form);
        return;
    }
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
    if matches!(
        browse.view,
        BrowseView::Hosts | BrowseView::Keys | BrowseView::Passwords
    ) {
        draw_ssh(frame, area, browse);
    } else {
        draw_entries(frame, area, browse);
    }
    match &browse.prompt {
        Prompt::Note { title, body } => draw_note(frame, area, title, body),
        Prompt::Line { title, value } => {
            if let Some(rect) = prompt_rect(area) {
                fill_line(frame, rect, input_line(title, value), raised());
            }
        }
        Prompt::SshForm(form) => {
            if let Some(rect) = prompt_rect(area) {
                fill_line(
                    frame,
                    rect,
                    input_line(&form.title(), &form.value),
                    raised(),
                );
            }
        }
        Prompt::Delete { path, kind } => draw_delete_dialog(frame, area, path, *kind),
        Prompt::HostEdit(_)
        | Prompt::PageForm(_)
        | Prompt::GetReview(_)
        | Prompt::Host(_)
        | Prompt::None => {}
    }
}

fn draw_ssh(frame: &mut Frame, area: Rect, browse: &Browse) {
    let (title, headers, rows) = match browse.ssh.pane {
        SshPane::Hosts => (
            "Hosts",
            &["tag", "target", "key"][..],
            browse.ssh.hosts.iter().map(host_cells).collect::<Vec<_>>(),
        ),
        SshPane::Keys => (
            "Keys",
            &["tag", "algorithm", "fingerprint", "comment"][..],
            browse.ssh.keys.iter().map(key_cells).collect::<Vec<_>>(),
        ),
        SshPane::Passwords => (
            "Passwords",
            &["tag", "length"][..],
            browse
                .ssh
                .passwords
                .iter()
                .map(password_cells)
                .collect::<Vec<_>>(),
        ),
    };
    let block = panel(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let widths = column_widths(headers, &rows, inner.width as usize);
    let header_cells: Vec<String> = headers.iter().map(|text| (*text).to_string()).collect();
    let header = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: 1,
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            format_columns(&header_cells, &widths),
            fg(MUTED).add_modifier(Modifier::BOLD),
        ))
        .style(surface()),
        header,
    );
    let list_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: inner.height.saturating_sub(1),
    };
    if rows.is_empty() {
        let empty = match browse.ssh.pane {
            SshPane::Hosts => "No hosts.",
            SshPane::Keys => "No keys.",
            SshPane::Passwords => "No passwords.",
        };
        frame.render_widget(
            Paragraph::new(Span::styled(empty, fg(MUTED))).style(surface()),
            list_area,
        );
        return;
    }
    let items: Vec<ListItem> = rows
        .iter()
        .map(|cells| ListItem::new(Span::styled(format_columns(cells, &widths), fg(TEXT))))
        .collect();
    let mut state = ListState::default();
    state.select(Some(browse.ssh.selected.min(items.len() - 1)));
    let list = List::new(items)
        .style(surface())
        .highlight_style(highlight());
    frame.render_stateful_widget(list, list_area, &mut state);
}

fn host_cells(row: &crate::ssh::HostRow) -> Vec<String> {
    vec![row.tag.clone(), row.target.clone(), row.key.clone()]
}

fn password_cells(row: &crate::ssh::PasswordRow) -> Vec<String> {
    let length = match row.length {
        Some(length) => length.to_string(),
        None => "invalid".into(),
    };
    vec![row.tag.clone(), length]
}

fn key_cells(row: &crate::ssh::KeyRow) -> Vec<String> {
    match &row.detail {
        crate::ssh::KeyDetail::Ready(info) => vec![
            row.tag.clone(),
            info.algorithm.clone(),
            info.fingerprint.clone(),
            info.comment.clone(),
        ],
        crate::ssh::KeyDetail::Raw => {
            vec![row.tag.clone(), "raw".into(), String::new(), String::new()]
        }
        crate::ssh::KeyDetail::Incomplete => {
            vec![
                row.tag.clone(),
                "incomplete".into(),
                String::new(),
                String::new(),
            ]
        }
        crate::ssh::KeyDetail::Invalid => {
            vec![
                row.tag.clone(),
                "invalid".into(),
                String::new(),
                String::new(),
            ]
        }
    }
}

fn column_widths(headers: &[&str], rows: &[Vec<String>], max_width: usize) -> Vec<usize> {
    let count = headers.len();
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate().take(count) {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    let gap = 2 * count.saturating_sub(1);
    let mut used = widths.iter().sum::<usize>() + gap;
    while used > max_width {
        let Some(index) = widths
            .iter()
            .enumerate()
            .filter(|(index, width)| **width > headers[*index].chars().count())
            .max_by_key(|(_, width)| *width)
            .map(|(index, _)| index)
        else {
            break;
        };
        let floor = headers[index].chars().count();
        let drop = (widths[index] - floor).min(used - max_width);
        widths[index] -= drop;
        used -= drop;
    }
    widths
}

fn format_columns(cells: &[String], widths: &[usize]) -> String {
    widths
        .iter()
        .enumerate()
        .map(|(index, width)| {
            let cell = cells.get(index).map(String::as_str).unwrap_or("");
            if cell.chars().count() > *width {
                fit(cell, *width)
            } else {
                format!("{cell:<width$}")
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
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

fn draw_delete_dialog(frame: &mut Frame, area: Rect, path: &str, kind: Kind) {
    let popup = dialog_area(area, 68, 8);
    frame.render_widget(Clear, popup);
    let block = shell(format!(" Delete {} ", kind.as_str()), surface());
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    if inner.is_empty() {
        return;
    }
    let path = fit(path, inner.width as usize);
    let lines = vec![
        Line::from(Span::styled(path, fg(TEXT).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled("enter ", fg(SAGE).add_modifier(Modifier::BOLD)),
            Span::styled("confirm", fg(TEXT)),
            Span::styled("    ", fg(MUTED)),
            Span::styled("esc ", fg(SAGE).add_modifier(Modifier::BOLD)),
            Span::styled("cancel", fg(TEXT)),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).style(surface()), inner);
}

fn draw_note(frame: &mut Frame, area: Rect, title: &str, body: &str) {
    let lines = note_lines(body, title == "keys");
    let height = (lines.len() as u16).saturating_add(2).clamp(6, 24);
    let popup = dialog_area(area, 68, height);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(shell(format!(" {title} "), surface()))
            .style(surface())
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

impl PasswdForm {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            current: Hidden::default(),
            next: Hidden::default(),
            again: Hidden::default(),
            cursor: 0,
        }
    }

    fn clear(&mut self) {
        self.current.clear();
        self.next.clear();
        self.again.clear();
        self.cursor = 0;
    }

    fn active(&mut self) -> &mut Hidden {
        match self.cursor {
            0 => &mut self.current,
            1 => &mut self.next,
            _ => &mut self.again,
        }
    }

    fn push(&mut self, ch: char) {
        self.active().push(ch);
    }

    fn pop(&mut self) {
        self.active().pop();
    }
}

impl FieldId {
    fn label(self, _block: bool) -> &'static str {
        match self {
            FieldId::Path => "Path",
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
            path_text: path.display().to_string(),
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

    /// New file volume. The path is the first field, starting in the working directory.
    fn new_file() -> Self {
        let path_text = new_volume_prefix();
        Self {
            path: PathBuf::from(path_text.trim()),
            path_text,
            block: false,
            fields: vec![
                FieldId::Path,
                FieldId::Size,
                FieldId::Password,
                FieldId::Again,
            ],
            cursor: 0,
            capacity: None,
            confirm: String::new(),
            size: String::new(),
            password: Hidden::default(),
            again: Hidden::default(),
        }
    }

    /// Resolve the typed path and, when it would overwrite data, ask for it again.
    fn apply_typed_path(&mut self) -> std::result::Result<(), String> {
        let text = self.path_text.trim();
        if text.is_empty() {
            return Err("enter a path".into());
        }
        let path = PathBuf::from(text);
        let block = super::is_block(&path);
        let needs_confirm = if block {
            true
        } else {
            match std::fs::metadata(&path) {
                Ok(meta) if meta.is_file() && meta.len() > 0 => true,
                Ok(meta) if meta.is_file() => false,
                Ok(_) => {
                    return Err("volume path is not a file or a block device".into());
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => false,
                Err(err) => return Err(err.to_string()),
            }
        };
        self.capacity = if block {
            Some(block_device_bytes(&path).map_err(|err| err.to_string())?)
        } else {
            None
        };
        self.path = path;
        self.block = block;
        if needs_confirm && !self.fields.contains(&FieldId::Confirm) {
            let at = self
                .fields
                .iter()
                .position(|field| *field == FieldId::Path)
                .map(|index| index + 1)
                .unwrap_or(0);
            self.fields.insert(at, FieldId::Confirm);
            self.cursor = at;
            return Err("retype the path to confirm".into());
        }
        if !needs_confirm {
            if let Some(index) = self
                .fields
                .iter()
                .position(|field| *field == FieldId::Confirm)
            {
                self.fields.remove(index);
                if self.cursor > index {
                    self.cursor -= 1;
                } else if self.cursor == index {
                    self.cursor = index.min(self.fields.len().saturating_sub(1));
                }
            }
        }
        Ok(())
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
            FieldId::Path => push_limited(&mut self.path_text, ch, 4096),
            FieldId::Confirm => push_limited(&mut self.confirm, ch, 4096),
            FieldId::Size => push_limited(&mut self.size, ch, 64),
            FieldId::Password => self.password.push(ch),
            FieldId::Again => self.again.push(ch),
        }
    }

    fn pop(&mut self) {
        match self.active() {
            FieldId::Path => {
                self.path_text.pop();
            }
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
            FieldId::Path => self.path_text.clone(),
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
            volume: Some(volume),
            cwd: "/".to_string(),
            entries: Vec::new(),
            selected: 0,
            marked: BTreeSet::new(),
            free: String::new(),
            prompt: Prompt::None,
            notice_pending: None,
            find: None,
            find_list_at: None,
            find_walk: None,
            find_after: None,
            view: BrowseView::Files,
            menu: VolumeMenu {
                open: false,
                cursor: 0,
            },
            ssh: SshLists {
                pane: SshPane::Hosts,
                hosts: Vec::new(),
                keys: Vec::new(),
                passwords: Vec::new(),
                selected: 0,
            },
            deferred: None,
            armed_session: None,
            overlay: None,
        };
        browse.reload_now();
        Ok(browse)
    }

    fn offload<F>(&mut self, title: &str, detail: String, work: F)
    where
        F: FnOnce(&mut Browse) + Send + 'static,
    {
        self.offload_paint(
            title,
            detail,
            None,
            Arc::new(AtomicU8::new(0)),
            Paint::Plain,
            work,
        );
    }

    fn offload_paint<F>(
        &mut self,
        title: &str,
        detail: String,
        watch: Option<Arc<InitWatch>>,
        cancel: CancelFlag,
        paint: Paint,
        work: F,
    ) where
        F: FnOnce(&mut Browse) + Send + 'static,
    {
        if run_here() {
            work(self);
            return;
        }
        self.deferred = Some(Deferred {
            title: title.to_string(),
            detail,
            watch,
            cancel,
            paint,
            work: Box::new(work),
        });
    }

    fn open_host_browser(&mut self) {
        let detail = self.cwd.clone();
        self.offload("Opening", detail, |browse| {
            browse.prompt = Prompt::Host(HostBrowser::start());
        });
    }

    fn begin_backup(&mut self, dest: PathBuf) {
        let watch = InitWatch::new();
        let watch_worker = Arc::clone(&watch);
        let cancel = Arc::new(AtomicU8::new(0));
        let cancel_worker = Arc::clone(&cancel);
        let detail = dest.display().to_string();
        self.offload_paint(
            "Backup",
            detail,
            Some(watch),
            cancel,
            Paint::Backup,
            move |browse| {
                let outcome = browse.vol().backup(&dest, &mut |done, total| {
                    watch_worker.set("backup", done, total);
                    if cancel_worker.load(Ordering::Relaxed) != 0 {
                        Err(Error::Message("backup canceled".into()))
                    } else {
                        Ok(())
                    }
                });
                match outcome {
                    Err(Error::Message(text)) if text == "backup canceled" => {}
                    Ok(bytes) => {
                        browse.prompt = Prompt::Note {
                            title: "Backup".into(),
                            body: format!("wrote {bytes} bytes to {}", dest.display()),
                        };
                    }
                    Err(err) => {
                        browse.prompt = Prompt::Note {
                            title: "Backup".into(),
                            body: err.to_string(),
                        };
                    }
                }
            },
        );
    }

    fn begin_health(&mut self) {
        let watch = InitWatch::new();
        let watch_worker = Arc::clone(&watch);
        let cancel = Arc::new(AtomicU8::new(0));
        let cancel_worker = Arc::clone(&cancel);
        let detail = self.volume_path.display().to_string();
        self.offload_paint(
            "Checking",
            detail,
            Some(watch),
            cancel,
            Paint::Health,
            move |browse| {
                let outcome = browse.vol().health(&mut |stage, done, total| {
                    watch_worker.set(stage, done, total);
                    if cancel_worker.load(Ordering::Relaxed) != 0 {
                        Err(Error::Message("health canceled".into()))
                    } else {
                        Ok(())
                    }
                });
                match outcome {
                    Err(Error::Message(text)) if text == "health canceled" => browse.reload_now(),
                    Ok(report) => {
                        browse.overlay = Some(Overlay::Health(HealthView {
                            stage: String::new(),
                            done: report.checked_blocks,
                            total: report.checked_blocks.max(1),
                            report: Some(report),
                            error: None,
                        }));
                    }
                    Err(err) => {
                        browse.overlay = Some(Overlay::Health(HealthView {
                            stage: String::new(),
                            done: 0,
                            total: 1,
                            report: None,
                            error: Some(err.to_string()),
                        }));
                    }
                }
            },
        );
    }

    fn reload(&mut self) {
        let detail = self.cwd.clone();
        self.offload("Opening", detail, |browse| browse.reload_now());
    }

    fn reload_now(&mut self) {
        let cwd = self.cwd.clone();
        match self.vol().list(&cwd) {
            Ok(entries) => {
                self.entries = entries;
                if self.selected >= self.entries.len() {
                    self.selected = self.entries.len().saturating_sub(1);
                }
            }
            Err(err) => self.fail(err),
        }
        match self.vol().stat(None) {
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
        let detail = self.cwd.clone();
        self.offload("Opening", detail, |browse| browse.go_up_now());
    }

    fn go_up_now(&mut self) {
        if self.cwd == "/" {
            return;
        }
        let leaving = self.cwd.rsplit('/').next().map(str::to_string);
        self.cwd = parent_path(&self.cwd);
        self.selected = 0;
        self.reload_now();
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
        let detail = self.cwd.clone();
        self.offload("Reading", detail, |browse| browse.start_get_now());
    }

    fn start_get_now(&mut self) {
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
            match self.vol().stat(Some(&src)) {
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
            self.prompt = Prompt::Note {
                title: "Delete".into(),
                body: "nothing selected".into(),
            };
            return;
        };
        let path = child_path(&self.cwd, &entry.name);
        let kind = entry.kind;
        self.prompt = Prompt::Delete { path, kind };
    }

    fn show_selected_stat(&mut self) {
        let detail = self.cwd.clone();
        self.offload("Reading", detail, |browse| browse.show_selected_stat_now());
    }

    fn show_selected_stat_now(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.show_volume_stat_now();
            return;
        };
        let path = child_path(&self.cwd, &entry.name);
        match self.vol().stat(Some(&path)) {
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
        let detail = self.volume_path.display().to_string();
        self.offload("Reading", detail, |browse| browse.show_volume_stat_now());
    }

    fn show_volume_stat_now(&mut self) {
        match self.vol().stat(None) {
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
        let Prompt::Delete { path, .. } = &self.prompt else {
            return;
        };
        let path = path.clone();
        self.prompt = Prompt::None;
        self.offload("Deleting", path.clone(), move |browse| {
            browse.delete_now(path);
        });
    }

    fn delete_now(&mut self, path: String) {
        match self.vol().delete(&path) {
            Ok(()) => self.reload_now(),
            Err(err) => {
                self.prompt = Prompt::Note {
                    title: "Delete".into(),
                    body: err.to_string(),
                };
                self.reload_now();
            }
        }
    }

    fn submit_line(&mut self) {
        let Prompt::Line { title, value } = &self.prompt else {
            return;
        };
        let title = *title;
        let value = value.trim().to_string();
        self.prompt = Prompt::None;
        if value.is_empty() {
            let note_title = match title {
                "backup path" => "Backup",
                "public key path" => "public key",
                _ => {
                    self.fail_msg("empty input");
                    return;
                }
            };
            self.prompt = Prompt::Note {
                title: note_title.into(),
                body: "empty input".into(),
            };
            return;
        }
        if title == "backup path" {
            self.begin_backup(PathBuf::from(value));
            return;
        }
        if title == "public key path" {
            self.save_public_key(PathBuf::from(value));
            return;
        }
        let path = child_path(&self.cwd, &value);
        self.offload("Creating", path.clone(), move |browse| {
            match browse.vol().mkdir(&path) {
                Ok(()) => {
                    browse.ok(format!("created {path}"));
                    browse.reload_now();
                }
                Err(err) => browse.fail(err),
            }
        });
    }

    fn push(&mut self, ch: char) {
        if let Prompt::HostEdit(editor) = &mut self.prompt {
            editor.push_char(ch);
            return;
        }
        if let Prompt::PageForm(form) = &mut self.prompt {
            form.push_char(ch);
            return;
        }
        if let Prompt::Line { value, .. } = &mut self.prompt {
            push_limited(value, ch, 4096);
            return;
        }
        if let Prompt::SshForm(form) = &mut self.prompt {
            push_limited(&mut form.value, ch, 64);
            return;
        }
        if matches!(
            &self.prompt,
            Prompt::Host(host)
                if host.confirm.is_none() && host.progress.is_none() && host.find.is_some()
        ) {
            self.queue_host_find_char(ch);
            return;
        }
        if matches!(self.prompt, Prompt::None) && self.find.is_some() {
            self.find_push(ch);
        }
    }

    fn queue_host_find_char(&mut self, ch: char) {
        let note = match &mut self.prompt {
            Prompt::Host(host) => host.edit_find_char(ch),
            _ => return,
        };
        self.arm_find_list(note);
    }

    fn queue_host_find_pop(&mut self) {
        let note = match &mut self.prompt {
            Prompt::Host(host) => host.edit_find_pop(),
            _ => return,
        };
        self.arm_find_list(note);
    }

    fn arm_find_list(&mut self, note: FindNote) {
        match note {
            FindNote::Unchanged => {}
            FindNote::Filtered => self.find_list_at = None,
            FindNote::Walk => self.find_list_at = Some(Instant::now() + FIND_LIST_WAIT),
        }
    }

    fn begin_find(&mut self) {
        if self.find.is_some() {
            return;
        }
        self.find_list_at = None;
        self.find = Some(VolumeFind {
            anchor: self.cwd.clone(),
            query: String::new(),
            needle: String::new(),
            stem: String::new(),
            cycling: false,
            resolved: String::new(),
            landed: true,
        });
    }

    fn find_push(&mut self, ch: char) {
        let changed = {
            let Some(find) = &mut self.find else {
                return;
            };
            let before = find.query.len();
            push_limited(&mut find.query, ch, 4096);
            if find.query.len() == before {
                false
            } else {
                find.cycling = false;
                true
            }
        };
        if changed {
            let note = self.classify_volume_find();
            self.arm_find_list(note);
        }
    }

    fn find_pop(&mut self) {
        let changed = {
            let Some(find) = &mut self.find else {
                return;
            };
            if find.query.pop().is_none() {
                false
            } else {
                find.cycling = false;
                true
            }
        };
        if changed {
            let note = self.classify_volume_find();
            self.arm_find_list(note);
        }
    }

    fn classify_volume_find(&mut self) -> FindNote {
        let edit = {
            let Some(find) = &self.find else {
                return FindNote::Unchanged;
            };
            find_edit(&find.resolved, find.landed, &find.query)
        };
        match edit {
            FindEdit::Filter(needle) => {
                self.apply_volume_filter(needle);
                FindNote::Filtered
            }
            FindEdit::Walk => FindNote::Walk,
        }
    }

    fn apply_volume_filter(&mut self, needle: String) {
        let old = self
            .find
            .as_ref()
            .map(|find| find.needle.clone())
            .unwrap_or_default();
        if old != needle {
            self.selected = 0;
        }
        if let Some(find) = &mut self.find {
            find.stem = query_stem(&find.query);
            find.needle = needle;
            find.cycling = false;
            find.resolved = find.query.clone();
            find.landed = true;
        }
    }

    fn vol(&mut self) -> &mut Volume {
        self.volume.as_mut().expect("volume is being listed")
    }

    fn find_pending(&self) -> bool {
        self.find_list_at.is_some() || self.find_walk.is_some()
    }

    /// Enter or Tab asked for the directory the query names. A walk already running keeps going.
    fn request_find_then(&mut self, then: FindThen) {
        self.find_after = Some(then);
        if self.find_walk.is_some() {
            return;
        }
        self.find_list_at = Some(Instant::now());
    }

    fn start_find_walk(&mut self) {
        if self.find_walk.is_some() {
            return;
        }
        if matches!(&self.prompt, Prompt::Host(host) if host.find.is_some()) {
            self.start_host_walk();
            return;
        }
        if self.find.is_some() {
            self.start_volume_walk();
        }
    }

    fn start_volume_walk(&mut self) {
        let Some(mut volume) = self.volume.take() else {
            return;
        };
        let Some(find) = &self.find else {
            self.volume = Some(volume);
            return;
        };
        let anchor = find.anchor.clone();
        let query = find.query.clone();
        let (tx, rx) = mpsc::channel();
        block_stop_signal();
        thread::spawn(move || {
            let _worker = WorkerFlag::enter();
            let walked = volume_follow(&mut volume, &anchor, &query);
            let (entries, error) = match volume.list(&walked.cwd) {
                Ok(entries) => (entries, String::new()),
                Err(err) => (Vec::new(), err.to_string()),
            };
            let free = match volume.stat(None) {
                Ok(Stat::Volume {
                    free_blocks,
                    free_payload_bytes,
                    ..
                }) => format!(
                    "free {free_blocks} blocks, {} payload",
                    human_bytes(free_payload_bytes)
                ),
                _ => String::new(),
            };
            let _ = tx.send(FindWalkOut::Volume(VolumeWalk {
                query,
                volume,
                cwd: walked.cwd,
                entries,
                needle: walked.needle,
                landed: walked.landed,
                free,
                error,
            }));
        });
        unblock_stop_signal();
        self.find_walk = Some(FindWalk { rx });
    }

    fn start_host_walk(&mut self) {
        let Prompt::Host(host) = &self.prompt else {
            return;
        };
        let Some(find) = &host.find else {
            return;
        };
        let anchor = find.anchor.clone();
        let query = find.query.clone();
        let (tx, rx) = mpsc::channel();
        block_stop_signal();
        thread::spawn(move || {
            let _worker = WorkerFlag::enter();
            let walked = follow_path(&anchor, &query);
            let (entries, error) = match list_host_dir(&walked.cwd) {
                Ok(entries) => (entries, String::new()),
                Err(err) => (Vec::new(), err),
            };
            let _ = tx.send(FindWalkOut::Host(HostWalk {
                query,
                cwd: walked.cwd,
                entries,
                needle: walked.needle,
                landed: walked.landed,
                error,
            }));
        });
        unblock_stop_signal();
        self.find_walk = Some(FindWalk { rx });
    }

    fn apply_find_walk(&mut self, outcome: FindWalkOut) {
        match outcome {
            FindWalkOut::Volume(walk) => self.apply_volume_walk(walk),
            FindWalkOut::Host(walk) => self.apply_host_walk(walk),
        }
    }

    fn apply_volume_walk(&mut self, walk: VolumeWalk) {
        self.volume = Some(walk.volume);
        if self.find_after == Some(FindThen::Cancel) {
            self.find_after = None;
            self.end_find(true);
            return;
        }
        if self.find.is_none() {
            return;
        }
        let cwd_changed = self.cwd != walk.cwd;
        if walk.error.is_empty() {
            self.entries = walk.entries;
        } else {
            self.fail_msg(walk.error);
            if cwd_changed {
                self.entries.clear();
            }
        }
        if cwd_changed {
            self.cwd = walk.cwd;
            self.selected = 0;
        } else if self.selected >= self.entries.len() {
            self.selected = self.entries.len().saturating_sub(1);
        }
        if !walk.free.is_empty() {
            self.free = walk.free;
        }
        let note = self.settle_volume_query(&walk.query, walk.needle, walk.landed);
        self.note_find_list(note);
        self.follow_find_after();
    }

    fn apply_host_walk(&mut self, walk: HostWalk) {
        if self.find_after == Some(FindThen::Cancel) {
            self.find_after = None;
            self.find_list_at = None;
            if let Prompt::Host(host) = &mut self.prompt {
                host.end_find(true);
            }
            return;
        }
        let note = match &mut self.prompt {
            Prompt::Host(host) => host.finish_walk(walk),
            _ => FindNote::Unchanged,
        };
        self.note_find_list(note);
        self.follow_find_after();
    }

    fn settle_volume_query(
        &mut self,
        walked_query: &str,
        walked_needle: String,
        walked_landed: bool,
    ) -> FindNote {
        let Some(find) = &self.find else {
            return FindNote::Unchanged;
        };
        let current = find.query.clone();
        let old_needle = find.needle.clone();
        let (needle, resolved, landed, note) =
            settle_find_query(&current, walked_query, walked_needle, walked_landed);
        if old_needle != needle {
            self.selected = 0;
        }
        if let Some(find) = &mut self.find {
            find.needle = needle;
            find.stem = query_stem(&find.query);
            find.cycling = false;
            find.resolved = resolved;
            find.landed = landed;
        }
        note
    }

    fn note_find_list(&mut self, note: FindNote) {
        match note {
            FindNote::Unchanged => {}
            FindNote::Filtered => self.find_list_at = None,
            FindNote::Walk => {
                if self.find_list_at.is_none() {
                    self.find_list_at = Some(Instant::now() + FIND_LIST_WAIT);
                }
            }
        }
    }

    fn follow_find_after(&mut self) {
        if self.find_list_at.is_some() || self.find_walk.is_some() {
            return;
        }
        let Some(then) = self.find_after.take() else {
            return;
        };
        match then {
            FindThen::Close => self.end_active_find(false),
            FindThen::Cancel => self.end_active_find(true),
            FindThen::Tab(delta) => self.tab_active_find(delta),
        }
    }

    fn end_active_find(&mut self, cancel: bool) {
        if matches!(&self.prompt, Prompt::Host(host) if host.find.is_some()) {
            if let Prompt::Host(host) = &mut self.prompt {
                host.end_find(cancel);
            }
            return;
        }
        self.end_find(cancel);
    }

    fn tab_active_find(&mut self, delta: isize) {
        if matches!(&self.prompt, Prompt::Host(host) if host.find.is_some()) {
            if let Prompt::Host(host) = &mut self.prompt {
                host.complete_tab(delta);
            }
            return;
        }
        self.complete_tab(delta);
    }

    fn end_find(&mut self, cancel: bool) {
        self.find_list_at = None;
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

    fn shows_menu(&self) -> bool {
        !matches!(self.prompt, Prompt::Host(_) | Prompt::GetReview(_))
    }

    fn ssh_len(&self) -> usize {
        match self.ssh.pane {
            SshPane::Hosts => self.ssh.hosts.len(),
            SshPane::Keys => self.ssh.keys.len(),
            SshPane::Passwords => self.ssh.passwords.len(),
        }
    }

    fn selected_host_tag(&self) -> Option<String> {
        self.ssh
            .hosts
            .get(self.ssh.selected)
            .map(|row| row.tag.clone())
    }

    fn selected_key_tag(&self) -> Option<String> {
        self.ssh
            .keys
            .get(self.ssh.selected)
            .map(|row| row.tag.clone())
    }

    fn selected_password_tag(&self) -> Option<String> {
        self.ssh
            .passwords
            .get(self.ssh.selected)
            .map(|row| row.tag.clone())
    }

    fn note_ssh(&mut self, body: String) {
        self.prompt = Prompt::Note {
            title: "ssh".into(),
            body,
        };
    }

    fn reload_ssh(&mut self) {
        let detail = self.volume_path.display().to_string();
        self.offload("Opening", detail, |browse| browse.reload_ssh_now());
    }

    fn reload_ssh_now(&mut self) {
        let mut error = None;
        match crate::ssh::list_hosts(self.vol()) {
            Ok(rows) => self.ssh.hosts = rows,
            Err(err) => {
                self.ssh.hosts.clear();
                error = Some(err.to_string());
            }
        }
        match crate::ssh::list_keys(self.vol()) {
            Ok(rows) => self.ssh.keys = rows,
            Err(err) => {
                self.ssh.keys.clear();
                error = Some(err.to_string());
            }
        }
        match crate::ssh::list_passwords(self.vol()) {
            Ok(rows) => self.ssh.passwords = rows,
            Err(err) => {
                self.ssh.passwords.clear();
                error = Some(err.to_string());
            }
        }
        let count = self.ssh_len();
        if self.ssh.selected >= count {
            self.ssh.selected = count.saturating_sub(1);
        }
        if let Some(body) = error {
            self.note_ssh(body);
        }
    }

    fn show_selected_host(&mut self) {
        let Some(tag) = self.selected_host_tag() else {
            self.note_ssh("nothing selected".into());
            return;
        };
        self.offload(
            "Reading",
            tag.clone(),
            move |browse| match crate::ssh::host_info(browse.vol(), &tag) {
                Ok(text) => {
                    browse.prompt = Prompt::Note {
                        title: "host".into(),
                        body: text,
                    };
                }
                Err(err) => browse.note_ssh(err.to_string()),
            },
        );
    }

    fn begin_public_download(&mut self) {
        let Some(tag) = self.selected_key_tag() else {
            self.note_ssh("nothing selected".into());
            return;
        };
        self.prompt = Prompt::Line {
            title: "public key path",
            value: suggested_public_path(&tag),
        };
    }

    fn save_public_key(&mut self, dest: PathBuf) {
        let Some(tag) = self.selected_key_tag() else {
            self.note_ssh("nothing selected".into());
            return;
        };
        let detail = dest.display().to_string();
        self.offload(
            "Saving",
            detail,
            move |browse| match crate::ssh::write_public_key(browse.vol(), &tag, &dest) {
                Ok(()) => {
                    browse.prompt = Prompt::Note {
                        title: "public key".into(),
                        body: format!("wrote {}", dest.display()),
                    };
                }
                Err(err) => {
                    browse.prompt = Prompt::Note {
                        title: "public key".into(),
                        body: err.to_string(),
                    };
                }
            },
        );
    }

    fn show_selected_key(&mut self) {
        let Some(tag) = self.selected_key_tag() else {
            self.note_ssh("nothing selected".into());
            return;
        };
        self.offload(
            "Reading",
            tag.clone(),
            move |browse| match crate::ssh::key_info(browse.vol(), &tag) {
                Ok(text) => {
                    browse.prompt = Prompt::Note {
                        title: "key".into(),
                        body: text,
                    };
                }
                Err(err) => browse.note_ssh(err.to_string()),
            },
        );
    }

    fn begin_ssh_new(&mut self) {
        self.prompt = match self.ssh.pane {
            SshPane::Hosts => Prompt::HostEdit(HostEditor::create()),
            SshPane::Keys => Prompt::PageForm(PageForm::create_key()),
            SshPane::Passwords => Prompt::PageForm(PageForm::password_add()),
        };
    }

    fn begin_password_generate(&mut self) {
        self.prompt = Prompt::PageForm(PageForm::password_generate());
    }

    fn copy_selected_password(&mut self) {
        let Some(tag) = self.selected_password_tag() else {
            self.note_ssh("nothing selected".into());
            return;
        };
        self.offload(
            "Copying",
            tag.clone(),
            move |browse| match crate::ssh::copy_password(browse.vol(), &tag) {
                Ok(()) => {
                    browse.prompt = Prompt::Note {
                        title: "password".into(),
                        body: format!("copied {tag}"),
                    };
                }
                Err(err) => browse.note_ssh(err.to_string()),
            },
        );
    }

    fn show_selected_password(&mut self) {
        let Some(row) = self.ssh.passwords.get(self.ssh.selected).cloned() else {
            self.note_ssh("nothing selected".into());
            return;
        };
        let body = match row.length {
            Some(length) => format!("tag: {}\nlength: {length}\n", row.tag),
            None => format!("tag: {}\ninvalid\n", row.tag),
        };
        self.prompt = Prompt::Note {
            title: "password".into(),
            body,
        };
    }

    fn dismiss_form(&mut self) {
        if let Prompt::SshForm(form) = &mut self.prompt {
            form.wipe();
        }
        self.prompt = Prompt::None;
    }

    fn begin_ssh_edit(&mut self) {
        if self.ssh.pane != SshPane::Hosts {
            return;
        }
        let Some(tag) = self.selected_host_tag() else {
            self.note_ssh("nothing selected".into());
            return;
        };
        self.offload(
            "Reading",
            tag.clone(),
            move |browse| match crate::ssh::load_host(browse.vol(), &tag) {
                Ok(host) => browse.open_host_editor(&tag, host),
                Err(err) => browse.note_ssh(err.to_string()),
            },
        );
    }

    fn open_host_editor(&mut self, tag: &str, host: crate::ssh::HostRecord) {
        self.prompt = Prompt::HostEdit(HostEditor {
            tag: tag.to_string(),
            key: host.key,
            hostname: host.hostname,
            user: host.user.unwrap_or_default(),
            port: host.port.map(|port| port.to_string()).unwrap_or_default(),
            timeout: host
                .timeout
                .map(|timeout| timeout.to_string())
                .unwrap_or_default(),
            options: host.options,
            cursor: 0,
            error: String::new(),
            create: false,
        });
    }

    fn move_host_editor(&mut self, delta: isize) {
        let Prompt::HostEdit(editor) = &mut self.prompt else {
            return;
        };
        let count = editor.field_count();
        if count == 0 {
            return;
        }
        editor.cursor = (editor.cursor as isize + delta).rem_euclid(count as isize) as usize;
    }

    fn drive_form(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                if matches!(self.prompt, Prompt::PageForm(_)) {
                    self.dismiss_form();
                } else {
                    self.prompt = Prompt::None;
                }
            }
            KeyCode::Enter => {
                if matches!(self.prompt, Prompt::HostEdit(_)) {
                    self.save_host_editor();
                } else {
                    self.save_page();
                }
            }
            KeyCode::Up | KeyCode::BackTab => self.nudge_form(-1),
            KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => self.nudge_form(-1),
            KeyCode::Down | KeyCode::Tab => self.nudge_form(1),
            KeyCode::Backspace => {
                if let Prompt::HostEdit(editor) = &mut self.prompt {
                    editor.pop_char();
                } else if let Prompt::PageForm(form) = &mut self.prompt {
                    form.pop_char();
                }
            }
            KeyCode::Char(ch) => {
                if let Prompt::HostEdit(editor) = &mut self.prompt {
                    editor.push_char(ch);
                } else if let Prompt::PageForm(form) = &mut self.prompt {
                    form.push_char(ch);
                }
            }
            _ => {}
        }
    }

    fn nudge_form(&mut self, delta: isize) {
        if matches!(self.prompt, Prompt::HostEdit(_)) {
            self.move_host_editor(delta);
            return;
        }
        if let Prompt::PageForm(form) = &mut self.prompt {
            form.move_cursor(delta);
        }
    }

    fn save_host_editor(&mut self) {
        let Prompt::HostEdit(editor) = &self.prompt else {
            return;
        };
        let editor = editor.clone();
        if let Err((logical, message)) = self.validate_host_editor(&editor) {
            if let Prompt::HostEdit(editor) = &mut self.prompt {
                editor.cursor = editor.focus(logical);
                editor.error = message;
            }
            return;
        }
        let detail = editor.tag.clone();
        let draft = editor.to_draft();
        self.prompt = Prompt::None;
        self.offload("Saving", detail, move |browse| browse.finish_host(draft));
    }

    fn validate_host_editor(
        &mut self,
        editor: &HostEditor,
    ) -> std::result::Result<(), (usize, String)> {
        if editor.create {
            if let Err(err) = crate::ssh::validate_tag(&editor.tag) {
                return Err((0, err.to_string()));
            }
            if self.path_exists(&format!("/ssh/hosts/{}", editor.tag)) {
                return Err((0, format!("host {} already exists", editor.tag)));
            }
        }
        if let Err(err) = crate::ssh::validate_tag(&editor.key) {
            return Err((1, err.to_string()));
        }
        if !self.path_exists(&format!("/ssh/keys/{}/meta", editor.key)) {
            return Err((1, format!("key {} was not found", editor.key)));
        }
        if let Err(err) = crate::ssh::validate_hostname(&editor.hostname) {
            return Err((2, err.to_string()));
        }
        if !editor.user.is_empty() {
            if let Err(err) = crate::ssh::validate_user(&editor.user) {
                return Err((3, err.to_string()));
            }
        }
        if !editor.port.is_empty() {
            if let Err(err) = crate::ssh::parse_port(&editor.port) {
                return Err((4, err.to_string()));
            }
        }
        if !editor.timeout.is_empty() {
            if let Err(err) = crate::ssh::parse_timeout(&editor.timeout) {
                return Err((5, err.to_string()));
            }
        }
        if editor
            .options
            .iter()
            .filter(|line| !line.is_empty())
            .count()
            > 64
        {
            return Err((6, "a host can have at most 64 options".into()));
        }
        for (index, line) in editor.options.iter().enumerate() {
            if line.is_empty() {
                continue;
            }
            if let Err(err) = crate::ssh::validate_option_line(line) {
                return Err((6 + index, err.to_string()));
            }
        }
        Ok(())
    }

    fn begin_ssh_add(&mut self) {
        self.prompt = Prompt::PageForm(PageForm::add_key());
    }

    fn begin_ssh_delete(&mut self) {
        let (pane, tag) = match self.ssh.pane {
            SshPane::Hosts => {
                let Some(tag) = self.selected_host_tag() else {
                    self.note_ssh("nothing selected".into());
                    return;
                };
                (SshPane::Hosts, tag)
            }
            SshPane::Keys => {
                let Some(tag) = self.selected_key_tag() else {
                    self.note_ssh("nothing selected".into());
                    return;
                };
                (SshPane::Keys, tag)
            }
            SshPane::Passwords => {
                let Some(tag) = self.selected_password_tag() else {
                    self.note_ssh("nothing selected".into());
                    return;
                };
                (SshPane::Passwords, tag)
            }
        };
        self.prompt = Prompt::SshForm(SshForm {
            pane,
            tag,
            value: String::new(),
        });
    }

    fn form_push(&mut self, ch: char) {
        if let Prompt::SshForm(form) = &mut self.prompt {
            push_limited(&mut form.value, ch, 64);
        }
    }

    fn form_pop(&mut self) {
        if let Prompt::SshForm(form) = &mut self.prompt {
            form.value.pop();
        }
    }

    fn submit_ssh_form(&mut self) {
        let Some(form) = self.take_ssh_form() else {
            return;
        };
        let detail = form.tag.clone();
        self.offload("Saving", detail, move |browse| {
            browse.submit_retype(form.pane, form.tag, form.value);
        });
    }

    fn take_ssh_form(&mut self) -> Option<SshForm> {
        match std::mem::replace(&mut self.prompt, Prompt::None) {
            Prompt::SshForm(form) => Some(form),
            other => {
                self.prompt = other;
                None
            }
        }
    }

    fn save_page(&mut self) {
        let (kind, mut values) = {
            let Prompt::PageForm(form) = &self.prompt else {
                return;
            };
            let values = form
                .fields
                .iter()
                .map(|field| field.value.clone())
                .collect::<Vec<_>>();
            (form.kind, values)
        };
        if let Err(issue) = self.check_page(kind, &values) {
            wipe_strings(&mut values);
            if let Prompt::PageForm(form) = &mut self.prompt {
                form.error = issue.message;
                form.cursor = issue.cursor;
                if issue.clear_secrets {
                    form.clear_secrets();
                }
            }
            return;
        }
        wipe_strings(&mut values);
        let Prompt::PageForm(form) = std::mem::replace(&mut self.prompt, Prompt::None) else {
            return;
        };
        let detail = form.detail();
        self.offload("Saving", detail, move |browse| browse.finish_page(form));
    }

    fn check_page(
        &mut self,
        kind: FormKind,
        values: &[String],
    ) -> std::result::Result<(), FormIssue> {
        match kind {
            FormKind::CreateKey => {
                if let Err(err) = crate::ssh::validate_tag(&values[0]) {
                    return Err(form_issue(0, err.to_string(), false));
                }
                Ok(())
            }
            FormKind::AddKey => {
                if let Err(err) = crate::ssh::validate_tag(&values[0]) {
                    return Err(form_issue(0, err.to_string(), false));
                }
                if self.key_present(&values[0]) {
                    return Err(form_issue(
                        0,
                        format!("key {} already exists", values[0]),
                        false,
                    ));
                }
                if values[1].is_empty() {
                    return Err(form_issue(1, "key file is required".into(), false));
                }
                Ok(())
            }
            FormKind::PasswordAdd => {
                self.check_password_tag(&values[0])?;
                if let Err(err) = crate::ssh::validate_stored_password(&values[1]) {
                    return Err(form_issue(1, err.to_string(), false));
                }
                if values[1] != values[2] {
                    return Err(form_issue(1, "passwords did not match".into(), true));
                }
                Ok(())
            }
            FormKind::PasswordGenerate => {
                self.check_password_tag(&values[0])?;
                if let Err(err) = crate::ssh::parse_password_length(&values[1]) {
                    return Err(form_issue(1, err.to_string(), false));
                }
                if let Err(err) = crate::ssh::parse_yes_no(&values[2]) {
                    return Err(form_issue(2, err.to_string(), false));
                }
                Ok(())
            }
        }
    }

    fn check_password_tag(&mut self, tag: &str) -> std::result::Result<(), FormIssue> {
        if let Err(err) = crate::ssh::password_tag_available(self.vol(), tag) {
            let message = match err {
                Error::AlreadyExists(text) => format!("already exists: {text}"),
                other => other.to_string(),
            };
            return Err(form_issue(0, message, false));
        }
        Ok(())
    }

    fn finish_page(&mut self, mut form: PageForm) {
        match form.kind {
            FormKind::CreateKey => {
                let tag = form.fields[0].value.clone();
                match crate::ssh::create_key(self.vol(), &tag, None) {
                    Ok(_) => {
                        self.prompt = Prompt::None;
                        self.reload_ssh();
                    }
                    Err(Error::AlreadyExists(text)) => {
                        form.error = format!("already exists: {text}");
                        form.cursor = 0;
                        self.prompt = Prompt::PageForm(form);
                    }
                    Err(err) => self.note_ssh(err.to_string()),
                }
            }
            FormKind::AddKey => {
                let tag = form.fields[0].value.clone();
                let path = form.fields[1].value.clone();
                match crate::ssh::add_key(self.vol(), &tag, Path::new(&path)) {
                    Ok(_) => {
                        self.prompt = Prompt::None;
                        self.reload_ssh();
                    }
                    Err(err) => {
                        form.error = err.to_string();
                        form.cursor = 1;
                        self.prompt = Prompt::PageForm(form);
                    }
                }
            }
            FormKind::PasswordAdd => {
                let tag = form.fields[0].value.clone();
                let mut secret = form.fields[1].value.clone();
                let saved = crate::ssh::add_password(self.vol(), &tag, &secret);
                secret.zeroize();
                match saved {
                    Ok(()) => {
                        self.prompt = Prompt::None;
                        self.reload_ssh();
                    }
                    Err(err) => {
                        form.error = err.to_string();
                        form.cursor = 1;
                        self.prompt = Prompt::PageForm(form);
                    }
                }
            }
            FormKind::PasswordGenerate => {
                let tag = form.fields[0].value.clone();
                let length = match crate::ssh::parse_password_length(&form.fields[1].value) {
                    Ok(length) => length,
                    Err(err) => {
                        form.error = err.to_string();
                        form.cursor = 1;
                        self.prompt = Prompt::PageForm(form);
                        return;
                    }
                };
                let symbols = match crate::ssh::parse_yes_no(&form.fields[2].value) {
                    Ok(symbols) => symbols,
                    Err(err) => {
                        form.error = err.to_string();
                        form.cursor = 2;
                        self.prompt = Prompt::PageForm(form);
                        return;
                    }
                };
                match crate::ssh::generate_password_record(self.vol(), &tag, length, symbols) {
                    Ok(()) => {
                        self.reload_ssh_now();
                        self.prompt = Prompt::Note {
                            title: "password".into(),
                            body: format!("generated {tag} and copied it"),
                        };
                    }
                    Err(err) => {
                        self.reload_ssh_now();
                        self.note_ssh(err.to_string());
                    }
                }
            }
        }
    }

    fn submit_retype(&mut self, pane: SshPane, tag: String, value: String) {
        if value != tag {
            self.note_ssh("confirmation did not match the tag".into());
            return;
        }
        let result = match pane {
            SshPane::Hosts => crate::ssh::delete_host(self.vol(), &tag),
            SshPane::Keys => crate::ssh::delete_key(self.vol(), &tag),
            SshPane::Passwords => crate::ssh::delete_password(self.vol(), &tag),
        };
        match result {
            Ok(()) => {
                self.prompt = Prompt::None;
                self.reload_ssh();
            }
            Err(err) => self.note_ssh(err.to_string()),
        }
    }

    fn finish_host(&mut self, draft: HostDraft) {
        let port = if draft.port.is_empty() {
            None
        } else {
            match crate::ssh::parse_port(&draft.port) {
                Ok(port) => Some(port),
                Err(err) => {
                    self.note_ssh(err.to_string());
                    return;
                }
            }
        };
        let timeout = if draft.timeout.is_empty() {
            None
        } else {
            match crate::ssh::parse_timeout(&draft.timeout) {
                Ok(timeout) => Some(timeout),
                Err(err) => {
                    self.note_ssh(err.to_string());
                    return;
                }
            }
        };
        let input = crate::ssh::HostInput {
            tag: draft.tag,
            key: draft.key,
            hostname: draft.hostname,
            user: if draft.user.is_empty() {
                None
            } else {
                Some(draft.user)
            },
            port,
            timeout,
            options: draft.options,
        };
        let saved = if draft.update {
            crate::ssh::update_host(self.vol(), &input)
        } else {
            crate::ssh::create_host(self.vol(), &input)
        };
        match saved {
            Ok(()) => {
                self.prompt = Prompt::None;
                self.reload_ssh();
            }
            Err(err) => self.note_ssh(err.to_string()),
        }
    }

    fn path_exists(&mut self, path: &str) -> bool {
        matches!(self.vol().stat(Some(path)), Ok(_))
    }

    fn key_present(&mut self, tag: &str) -> bool {
        self.path_exists(&format!("/ssh/keys/{tag}/private"))
            || self.path_exists(&format!("/ssh/keys/{tag}/meta"))
    }
}

impl SshForm {
    fn title(&self) -> String {
        format!("type {} to delete", self.tag)
    }

    fn wipe(&mut self) {
        self.value.zeroize();
    }
}

impl FormField {
    fn new(label: &'static str, secret: bool, limit: usize) -> Self {
        Self {
            label,
            value: String::new(),
            secret,
            limit,
        }
    }

    fn shown(&self) -> String {
        if self.secret {
            "●".repeat(self.value.chars().count())
        } else {
            self.value.clone()
        }
    }
}

impl PageForm {
    fn create_key() -> Self {
        Self::new(
            "New key",
            "",
            FormKind::CreateKey,
            vec![FormField::new("tag", false, 64)],
        )
    }

    fn add_key() -> Self {
        Self::new(
            "Add key",
            "Path to an OpenSSH private key.",
            FormKind::AddKey,
            vec![
                FormField::new("tag", false, 64),
                FormField::new("file", false, 4096),
            ],
        )
    }

    fn password_add() -> Self {
        Self::new(
            "New password",
            "",
            FormKind::PasswordAdd,
            vec![
                FormField::new("tag", false, 64),
                FormField::new("password", true, 1024),
                FormField::new("confirm", true, 1024),
            ],
        )
    }

    fn password_generate() -> Self {
        Self::new(
            "Generate password",
            "Length is 8 to 128. Symbols is y or n.",
            FormKind::PasswordGenerate,
            vec![
                FormField::new("tag", false, 64),
                FormField::new("length", false, 3),
                FormField::new("symbols", false, 3),
            ],
        )
    }

    fn new(
        title: &'static str,
        hint: &'static str,
        kind: FormKind,
        fields: Vec<FormField>,
    ) -> Self {
        Self {
            title,
            hint,
            fields,
            cursor: 0,
            error: String::new(),
            kind,
        }
    }

    fn detail(&self) -> String {
        self.fields
            .first()
            .map(|field| field.value.clone())
            .unwrap_or_default()
    }

    fn move_cursor(&mut self, delta: isize) {
        let count = self.fields.len();
        if count == 0 {
            return;
        }
        self.cursor = (self.cursor as isize + delta).rem_euclid(count as isize) as usize;
    }

    fn push_char(&mut self, ch: char) {
        self.error.clear();
        let Some(field) = self.fields.get_mut(self.cursor) else {
            return;
        };
        let limit = field.limit;
        push_limited(&mut field.value, ch, limit);
    }

    fn pop_char(&mut self) {
        self.error.clear();
        let Some(field) = self.fields.get_mut(self.cursor) else {
            return;
        };
        field.value.pop();
    }

    fn clear_secrets(&mut self) {
        for field in &mut self.fields {
            if field.secret {
                field.value.zeroize();
            }
        }
    }
}

impl Drop for PageForm {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

impl HostEditor {
    fn create() -> Self {
        Self {
            tag: String::new(),
            key: String::new(),
            hostname: String::new(),
            user: String::new(),
            port: String::new(),
            timeout: String::new(),
            options: Vec::new(),
            cursor: 0,
            error: String::new(),
            create: true,
        }
    }

    /// `logical` counts the tag as 0, including when that row is not editable.
    fn focus(&self, logical: usize) -> usize {
        let cursor = if self.create {
            logical
        } else {
            logical.saturating_sub(1)
        };
        cursor.min(self.field_count().saturating_sub(1))
    }

    fn logical(&self) -> usize {
        if self.create {
            self.cursor
        } else {
            self.cursor + 1
        }
    }

    fn field_count(&self) -> usize {
        let fixed = if self.create { 6 } else { 5 };
        fixed + self.options.len() + 1
    }

    fn fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = Vec::new();
        if self.create {
            fields.push(("tag", self.tag.clone()));
        }
        fields.extend([
            ("key", self.key.clone()),
            ("hostname", self.hostname.clone()),
            ("user", self.user.clone()),
            ("port", self.port.clone()),
            ("timeout", self.timeout.clone()),
        ]);
        for option in &self.options {
            fields.push(("option", option.clone()));
        }
        fields.push(("option", String::new()));
        fields
    }

    fn byte_limit(&self) -> usize {
        match self.logical() {
            0 | 1 => 64,
            2 => 255,
            3 => 64,
            4 => 5,
            5 => 4,
            _ => 1024,
        }
    }

    fn on_blank_option(&self) -> bool {
        let logical = self.logical();
        logical >= 6 && logical - 6 == self.options.len()
    }

    fn push_char(&mut self, ch: char) {
        self.error.clear();
        let limit = self.byte_limit();
        if self.on_blank_option() {
            if self.options.len() >= 64 {
                self.error = "a host can have at most 64 options".into();
                return;
            }
            let mut value = String::new();
            push_limited(&mut value, ch, limit);
            if !value.is_empty() {
                self.options.push(value);
            }
            return;
        }
        if let Some(value) = self.value_mut() {
            push_limited(value, ch, limit);
        }
    }

    fn pop_char(&mut self) {
        self.error.clear();
        if self.on_blank_option() {
            return;
        }
        if let Some(value) = self.value_mut() {
            value.pop();
        }
    }

    fn value_mut(&mut self) -> Option<&mut String> {
        match self.logical() {
            0 => Some(&mut self.tag),
            1 => Some(&mut self.key),
            2 => Some(&mut self.hostname),
            3 => Some(&mut self.user),
            4 => Some(&mut self.port),
            5 => Some(&mut self.timeout),
            index => self.options.get_mut(index - 6),
        }
    }

    fn to_draft(&self) -> HostDraft {
        HostDraft {
            tag: self.tag.clone(),
            key: self.key.clone(),
            hostname: self.hostname.clone(),
            user: self.user.clone(),
            port: self.port.clone(),
            timeout: self.timeout.clone(),
            options: self
                .options
                .iter()
                .filter(|line| !line.is_empty())
                .cloned()
                .collect(),
            update: !self.create,
        }
    }
}

fn form_issue(cursor: usize, message: String, clear_secrets: bool) -> FormIssue {
    FormIssue {
        cursor,
        message,
        clear_secrets,
    }
}

fn wipe_strings(values: &mut [String]) {
    for value in values {
        value.zeroize();
    }
}

fn prepare_user_terminal() {
    const LEAVE: &[u8] =
        b"\x1b[?1049l\x1b[0m\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[2J\x1b[H";
    let _ = io::stdout().write_all(LEAVE);
    let _ = io::stdout().flush();
    restore_saved_termios(libc::TCSADRAIN);
}

fn startup_termios_hex() -> String {
    if !TERMIOS_READY.load(Ordering::Acquire) {
        return String::new();
    }
    unsafe {
        let bytes = std::slice::from_raw_parts(
            std::ptr::addr_of!(SAVED_TERMIOS) as *const u8,
            std::mem::size_of::<libc::termios>(),
        );
        crate::ssh::encode_hex(bytes)
    }
}

fn restore_saved_termios(action: libc::c_int) {
    if !TERMIOS_READY.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        libc::tcsetattr(
            libc::STDIN_FILENO,
            action,
            std::ptr::addr_of!(SAVED_TERMIOS),
        );
    }
}

fn resume_terminal(terminal: &mut Term) -> Result<()> {
    unsafe {
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }
    claim_foreground();
    // ssh saves the mode it sees at startup and writes it back on exit. That
    // can be the raw mode from the connecting screen. Put the cooked mode back
    // first, then let crossterm save that as the mode it will restore on quit.
    let _ = disable_raw_mode();
    restore_saved_termios(libc::TCSANOW);
    enable_raw_mode().map_err(Error::Io)?;
    execute!(io::stdout(), EnterAlternateScreen, Hide).map_err(Error::Io)?;
    let _ = io::stdout().flush();
    terminal.clear().map_err(Error::Io)?;
    Ok(())
}

fn cancel_keymap() -> Line<'static> {
    keymap(&[("esc", "cancel"), ("q", "cancel"), ("ctrl-c", "cancel")])
}

fn loader_frame(elapsed: Duration) -> char {
    let ticks = (elapsed.as_millis() / LOADER_STEP_MS) as usize;
    LOADER_FRAMES[ticks % LOADER_FRAMES.len()]
}

fn format_elapsed(elapsed: Duration) -> String {
    let total = elapsed.as_secs();
    let mins = total / 60;
    let secs = total % 60;
    if mins == 0 {
        format!("{secs}s")
    } else {
        format!("{mins}m{secs:02}s")
    }
}

fn loader_message(title: &str, detail: &str) -> String {
    let title = title.trim();
    let detail = detail.trim();
    if title.is_empty() {
        detail.to_string()
    } else if detail.is_empty() || detail == title {
        title.to_string()
    } else {
        format!("{title}  {detail}")
    }
}

fn loader_line(title: &str, detail: &str, elapsed: Duration, width: usize) -> Line<'static> {
    let spin = loader_frame(elapsed);
    let time = format_elapsed(elapsed);
    let prefix = 1 + 1 + 2 + time.chars().count() + 2;
    let message = fit(&loader_message(title, detail), width.saturating_sub(prefix));
    Line::from(vec![
        Span::styled(
            format!(" {spin}  "),
            fg(SAGE).bg(RAISED).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{time}  "), fg(MUTED).bg(RAISED)),
        Span::styled(message, fg(TEXT).bg(RAISED)),
    ])
}

fn draw_loader_bar(frame: &mut Frame, area: Rect, loader: &LoaderView) {
    if area.is_empty() {
        return;
    }
    let line = loader_line(
        &loader.title,
        &loader.detail,
        loader.elapsed,
        area.width as usize,
    );
    frame.render_widget(Paragraph::new(line).style(raised()), area);
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
menu: m opens files, hosts, keys, and passwords. j or k moves, enter opens, esc closes
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
delete: d or delete asks about the file or directory under the cursor
enter confirms that delete, esc cancels it
stat: i for the selection, v for the volume
health: b checks every block and repairs what it can
during that check: esc, q, or ctrl-c returns here
when the report is up: enter, esc, or q closes it
backup: w asks for a path and a file name, then copies this volume byte for byte
during that copy: esc, q, or ctrl-c stops it and removes the partial file
find: / opens a path field here and in the file pickers
filter: typed text narrows the open directory at once
slash: / at the end of a name opens that directory after you pause
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

struct Walked<T> {
    cwd: T,
    needle: String,
    /// Every completed path component was entered.
    landed: bool,
}

enum FindEdit {
    /// The open directory is unchanged. `needle` filters it in memory.
    Filter(String),
    /// A directory may have to be read.
    Walk,
}

/// Keeps characters typed while a directory walk was in flight.
fn settle_find_query(
    current: &str,
    walked_query: &str,
    walked_needle: String,
    walked_landed: bool,
) -> (String, String, bool, FindNote) {
    if current == walked_query {
        return (
            walked_needle,
            walked_query.to_string(),
            walked_landed,
            FindNote::Filtered,
        );
    }
    match find_edit(walked_query, walked_landed, current) {
        FindEdit::Filter(needle) => (needle, current.to_string(), true, FindNote::Filtered),
        FindEdit::Walk => (
            walked_needle,
            walked_query.to_string(),
            walked_landed,
            FindNote::Walk,
        ),
    }
}

fn find_edit(resolved: &str, landed: bool, query: &str) -> FindEdit {
    let previous = path_steps(resolved);
    let next = path_steps(query);
    if landed && previous.absolute == next.absolute && previous.enter == next.enter {
        FindEdit::Filter(next.needle)
    } else {
        FindEdit::Walk
    }
}

fn volume_follow(volume: &mut Volume, anchor: &str, query: &str) -> Walked<String> {
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
            _ => {
                return Walked {
                    cwd,
                    needle: name,
                    landed: false,
                };
            }
        }
    }
    Walked {
        cwd,
        needle: steps.needle,
        landed: true,
    }
}

fn follow_path(anchor: &Path, query: &str) -> Walked<PathBuf> {
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
            return Walked {
                cwd,
                needle: name,
                landed: false,
            };
        }
    }
    Walked {
        cwd,
        needle: steps.needle,
        landed: true,
    }
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

struct DiskWidths {
    path: usize,
    size: usize,
    kind: usize,
    model: usize,
    flag: usize,
}

fn disk_widths(disks: &[Disk], max_width: usize) -> DiskWidths {
    let size = disks
        .iter()
        .map(|disk| human_bytes(disk.bytes).chars().count())
        .max()
        .unwrap_or(0);
    let kind = 4;
    let mut flag = if disks.iter().any(|disk| disk.removable) {
        "removable".chars().count()
    } else {
        0
    };
    let mut path = disks
        .iter()
        .map(|disk| disk.path.chars().count())
        .max()
        .unwrap_or(0);
    let mut model = disks
        .iter()
        .map(|disk| disk.model.chars().count())
        .max()
        .unwrap_or(0);
    let path_floor = path.min(12);
    let model_floor = model.min(12);
    while disk_row_width(path, size, kind, model, flag) > max_width {
        let path_extra = path.saturating_sub(path_floor);
        let model_extra = model.saturating_sub(model_floor);
        if path_extra == 0 && model_extra == 0 {
            if model > 0 {
                model -= 1;
            } else if path > 1 {
                path -= 1;
            } else if flag > 0 {
                flag = 0;
            } else {
                break;
            }
            continue;
        }
        if path_extra >= model_extra && path_extra > 0 {
            path -= 1;
        } else {
            model -= 1;
        }
    }
    DiskWidths {
        path,
        size,
        kind,
        model,
        flag,
    }
}

fn disk_row_width(path: usize, size: usize, kind: usize, model: usize, flag: usize) -> usize {
    let mut total = 0;
    let mut columns = 0;
    for width in [path, size, kind, model, flag] {
        if width == 0 {
            continue;
        }
        if columns > 0 {
            total += 2;
        }
        total += width;
        columns += 1;
    }
    total
}

fn disk_row(disk: &Disk, widths: &DiskWidths) -> Line<'static> {
    let kind = if disk.file {
        "file"
    } else if disk.partition {
        "part"
    } else {
        "disk"
    };
    let kind_style = if disk.file || disk.removable {
        fg(SAGE)
    } else {
        fg(MUTED)
    };
    let mut spans = Vec::new();
    push_col(
        &mut spans,
        &fit_tail(&disk.path, widths.path),
        widths.path,
        fg(TEXT),
        false,
    );
    push_col(
        &mut spans,
        &human_bytes(disk.bytes),
        widths.size,
        fg(MUTED),
        true,
    );
    push_col(&mut spans, kind, widths.kind, kind_style, false);
    if widths.model > 0 {
        push_col(&mut spans, &disk.model, widths.model, fg(MUTED), false);
    }
    if widths.flag > 0 {
        let flag = if disk.removable { "removable" } else { "" };
        push_col(&mut spans, flag, widths.flag, fg(SAGE), false);
    }
    Line::from(spans)
}

fn push_col(spans: &mut Vec<Span<'static>>, text: &str, width: usize, style: Style, right: bool) {
    if width == 0 {
        return;
    }
    if !spans.is_empty() {
        spans.push(Span::raw("  "));
    }
    let cell = if right {
        pad_start(text, width)
    } else {
        pad_end(text, width)
    };
    spans.push(Span::styled(cell, style));
}

fn pick_summary(disks: &[Disk]) -> String {
    let files = disks.iter().filter(|disk| disk.file).count();
    let devices = disks.len() - files;
    match (files, devices) {
        (0, 1) => "1 disk".to_string(),
        (0, n) => format!("{n} disks"),
        (1, 0) => "1 file".to_string(),
        (n, 0) => format!("{n} files"),
        (1, 1) => "1 file, 1 disk".to_string(),
        (1, n) => format!("1 file, {n} disks"),
        (n, 1) => format!("{n} files, 1 disk"),
        (files, devices) => format!("{files} files, {devices} disks"),
    }
}

/// Volumes to show on the first page: HDNFS files in the working directory, then block devices.
fn list_pick_entries() -> Vec<Disk> {
    let mut entries = match std::env::current_dir() {
        Ok(dir) => list_volume_files(&dir),
        Err(_) => Vec::new(),
    };
    entries.extend(list_disks());
    entries
}

/// Initialized HDNFS files directly inside `dir`. Subdirectories are not searched.
fn list_volume_files(dir: &Path) -> Vec<Disk> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_file() {
            continue;
        }
        let path = entry.path();
        if !matches!(has_volume_magic(&path), Ok(true)) {
            continue;
        }
        let bytes = entry.metadata().map(|meta| meta.len()).unwrap_or(0);
        files.push(Disk {
            path: path.display().to_string(),
            bytes,
            model: String::new(),
            removable: false,
            partition: false,
            file: true,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files
}

fn new_volume_prefix() -> String {
    let Ok(dir) = std::env::current_dir() else {
        return String::new();
    };
    let mut text = dir.display().to_string();
    if !text.ends_with('/') {
        text.push('/');
    }
    text
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
        file: false,
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

fn probe_path(path: PathBuf, after: AfterAccess) -> ProbeOut {
    if !path.exists() {
        return match after {
            AfterAccess::Passwd => ProbeOut::Failed(Error::NotAVolume.to_string()),
            _ => setup_or_fail(path),
        };
    }
    match super::sudo_password_needed(&path) {
        Ok(true) => ProbeOut::Sudo { path, after },
        Ok(false) => finish_probe(path, after),
        Err(err) => ProbeOut::Failed(err.to_string()),
    }
}

fn finish_probe(path: PathBuf, after: AfterAccess) -> ProbeOut {
    match after {
        AfterAccess::Initialize => setup_or_fail(path),
        AfterAccess::Open => classify_path(path),
        AfterAccess::Passwd => passwd_or_fail(path),
    }
}

fn passwd_or_fail(path: PathBuf) -> ProbeOut {
    match has_volume_magic(&path) {
        Ok(true) => ProbeOut::Passwd(path),
        Ok(false) => ProbeOut::Failed(Error::NotAVolume.to_string()),
        Err(err) => ProbeOut::Failed(err.to_string()),
    }
}

fn classify_path(path: PathBuf) -> ProbeOut {
    match has_volume_magic(&path) {
        Ok(true) => ProbeOut::Unlock(path),
        Ok(false) => setup_or_fail(path),
        Err(err) => ProbeOut::Failed(err.to_string()),
    }
}

fn setup_or_fail(path: PathBuf) -> ProbeOut {
    match Setup::create(path) {
        Ok(setup) => ProbeOut::Setup(setup),
        Err(err) => ProbeOut::Failed(err.to_string()),
    }
}

fn run_init(plan: SetupPlan, watch: Arc<InitWatch>, cancel: CancelFlag) -> JobOut {
    let path = plan.path.clone();
    let mut password = plan.password.expose().to_string();
    let mut on_progress = |stage: &str, done: u64, total: u64| {
        if cancel.load(Ordering::Relaxed) != 0 {
            return Err(Error::Message("initialization canceled".into()));
        }
        watch.set(stage, done, total);
        Ok(())
    };
    let initialized = init_volume(InitOptions {
        path: &path,
        password: &password,
        size: plan.size,
        force: plan.force,
        kdf: KdfParams::default(),
        progress: Some(&mut on_progress),
    });
    let browse = match initialized {
        Ok(_) => Volume::open(&path, &password, LockMode::Exclusive)
            .and_then(|volume| Browse::open(path, volume))
            .map_err(|err| err.to_string()),
        Err(err) => Err(err.to_string()),
    };
    password.zeroize();
    JobOut::Initialized { browse }
}

fn perform_put(
    browse: &mut Browse,
    volume_cwd: &str,
    marked: &[PathBuf],
    watch: &InitWatch,
    cancel: &AtomicU8,
) {
    watch.set("reading", 0, 1);
    let plan = match plan_puts(volume_cwd, marked) {
        Ok(plan) => plan,
        Err(err) => {
            browse.fail_msg(err);
            return;
        }
    };
    let skipped = plan.skipped;
    let ops = plan.ops;
    if ops.is_empty() {
        browse.fail_msg("nothing to store");
        return;
    }
    if let Err(err) = browse.vol().begin_batch() {
        browse.fail(err);
        return;
    }
    let total = ops.len() as u64;
    let mut stop = CopyStop::Done;
    for (index, op) in ops.iter().enumerate() {
        watch.set(op.label(), index as u64, total);
        match cancel.load(Ordering::Relaxed) {
            0 => {}
            2 => {
                stop = CopyStop::Close(index as u64);
                break;
            }
            _ => {
                stop = CopyStop::Cancel(index as u64);
                break;
            }
        }
        if let Err(err) = stage_one(browse.vol(), op) {
            stop = CopyStop::Failed(err.to_string());
            break;
        }
    }
    let commit_error = browse.vol().finish_batch().err().map(|err| err.to_string());
    finish_put(browse, &stop, commit_error, &ops, volume_cwd, &skipped);
}

fn stage_one(volume: &mut Volume, op: &PutOp) -> Result<()> {
    match op {
        PutOp::Mkdir(path) => volume.stage_mkdir(path),
        PutOp::File { host, dest } => {
            volume.stage_put(host, dest)?;
            Ok(())
        }
    }
}

fn finish_put(
    browse: &mut Browse,
    stop: &CopyStop,
    commit_error: Option<String>,
    ops: &[PutOp],
    volume_cwd: &str,
    skipped: &[PathBuf],
) {
    if matches!(stop, CopyStop::Close(_)) {
        if let Prompt::Host(host) = &mut browse.prompt {
            host.marked.clear();
            host.progress = None;
        }
        browse.prompt = Prompt::None;
    }
    if commit_error.is_none() && matches!(stop, CopyStop::Done) {
        browse.prompt = Prompt::None;
    }
    browse.reload_now();
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
    if let Some(err) = commit_error {
        browse.fail_msg(err);
        return;
    }
    match stop {
        CopyStop::Cancel(index) | CopyStop::Close(index) => {
            browse.fail_msg(format!("put canceled after {index} of {}", ops.len()));
        }
        CopyStop::Failed(err) => browse.fail_msg(err.clone()),
        CopyStop::Done => {}
    }
}

fn perform_get(
    browse: &mut Browse,
    dest_dir: PathBuf,
    paint: Arc<Mutex<GetPaint>>,
    cancel: CancelFlag,
) {
    if !dest_dir.is_dir() {
        if let Prompt::Host(host) = &mut browse.prompt {
            host.confirm = None;
            host.error = format!("{} is not a directory", dest_dir.display());
        }
        return;
    }
    let mut canceled = false;
    let count = paint
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .items
        .len();
    for index in 0..count {
        if cancel.load(Ordering::Relaxed) != 0 {
            canceled = true;
            break;
        }
        let (src, dest) = {
            let mut items = paint.lock().unwrap_or_else(|err| err.into_inner());
            items.items[index].phase = GetPhase::Active;
            items.items[index].written = 0;
            (
                items.items[index].src.clone(),
                items.items[index].dest.clone(),
            )
        };
        let paint_cb = Arc::clone(&paint);
        let cancel_cb = Arc::clone(&cancel);
        let copied = browse.vol().get_with(&src, &dest, &mut |written, total| {
            {
                let mut items = paint_cb.lock().unwrap_or_else(|err| err.into_inner());
                items.items[index].written = written;
                if total > 0 {
                    items.items[index].size = total;
                }
            }
            if cancel_cb.load(Ordering::Relaxed) != 0 {
                Err(Error::Message("get canceled".into()))
            } else {
                Ok(())
            }
        });
        let mut items = paint.lock().unwrap_or_else(|err| err.into_inner());
        match copied {
            Ok(_) => {
                items.items[index].phase = GetPhase::Done;
                items.items[index].written = items.items[index].size;
            }
            Err(Error::Message(text)) if text == "get canceled" => {
                items.items[index].phase = GetPhase::Pending;
                items.items[index].written = 0;
                canceled = true;
            }
            Err(err) => {
                items.items[index].phase = GetPhase::Failed;
                items.items[index].error = err.to_string();
            }
        }
        if canceled {
            break;
        }
    }
    let items = paint
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .items
        .clone();
    let done = items
        .iter()
        .filter(|item| matches!(item.phase, GetPhase::Done))
        .count();
    let total = items.len();
    let failure = items
        .iter()
        .find(|item| matches!(item.phase, GetPhase::Failed))
        .cloned();
    for item in &items {
        if matches!(item.phase, GetPhase::Done) {
            browse.marked.remove(&item.src);
        }
    }
    browse.prompt = Prompt::None;
    browse.overlay = Some(Overlay::Get {
        items,
        dest: dest_dir.clone(),
    });
    if canceled {
        browse.fail_msg(format!("get canceled after {done} of {total}"));
    } else if let Some(failed) = failure {
        browse.fail_msg(format!("{}: {}", failed.name, failed.error));
    } else {
        let noun = if done == 1 { "file" } else { "files" };
        browse.ok(format!("got {done} {noun} into {}", dest_dir.display()));
    }
}

fn cancel_code(key: &KeyEvent) -> Option<u8> {
    if key.code == KeyCode::Esc {
        return Some(2);
    }
    let stop = key.code == KeyCode::Char('q')
        || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c'));
    if stop {
        Some(1)
    } else {
        None
    }
}

fn stage_line(stage: &str) -> String {
    match stage {
        "writing" => "Writing free space".to_string(),
        "sealing" => "Sealing the volume".to_string(),
        "deriving" => "Deriving the volume key".to_string(),
        "reading" => "Reading the selection".to_string(),
        other => other.to_string(),
    }
}

fn draw_backup_progress(frame: &mut Frame, dest: &str, done: u64, total: u64) {
    paint_screen(frame);
    let [header, body, help] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    paint_banner(frame, header, "Backup", dest);
    let ratio = if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    };
    draw_meter(
        frame,
        body,
        "Copying",
        dest,
        "Each byte of the volume image is copied in order.",
        ratio,
        &format!("{} / {}", human_bytes(done), human_bytes(total)),
    );
    frame.render_widget(
        Paragraph::new(keymap(&[
            ("esc", "cancel"),
            ("q", "cancel"),
            ("ctrl-c", "cancel"),
        ]))
        .style(chrome(false)),
        help,
    );
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
        0.0
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
        Paragraph::new(keymap(&[
            ("esc", "cancel"),
            ("q", "cancel"),
            ("ctrl-c", "cancel"),
        ]))
        .style(chrome(false)),
        help,
    );
}

fn stage_detail(stage: &str) -> &'static str {
    match stage {
        "writing" => "Free space is filled before the volume is sealed.",
        "sealing" => "The superblock is written and synced.",
        "deriving" => "The volume key is derived from the password.",
        "reading" => "The selection is walked before anything is written.",
        _ => "The screen stays live while this runs.",
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
    let block = shell(format!(" {title} "), surface()).padding(Padding::horizontal(2));
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
        .style(surface())
        .wrap(Wrap { trim: false }),
        text,
    );
    paint_bar(frame, bar, ratio, &format!("{pct}%"));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(meta.to_string(), fg(MUTED)))).style(surface()),
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
            resolved: String::new(),
            landed: true,
        });
    }

    fn type_find(&mut self, ch: char) -> bool {
        let Some(find) = &mut self.find else {
            return false;
        };
        let before = find.query.len();
        push_limited(&mut find.query, ch, 4096);
        if find.query.len() == before {
            return false;
        }
        find.cycling = false;
        true
    }

    fn edit_find_char(&mut self, ch: char) -> FindNote {
        if !self.type_find(ch) {
            return FindNote::Unchanged;
        }
        self.classify_find()
    }

    fn edit_find_pop(&mut self) -> FindNote {
        let changed = {
            let Some(find) = &mut self.find else {
                return FindNote::Unchanged;
            };
            if find.query.pop().is_none() {
                false
            } else {
                find.cycling = false;
                true
            }
        };
        if !changed {
            return FindNote::Unchanged;
        }
        self.classify_find()
    }

    fn classify_find(&mut self) -> FindNote {
        let edit = {
            let Some(find) = &self.find else {
                return FindNote::Unchanged;
            };
            find_edit(&find.resolved, find.landed, &find.query)
        };
        match edit {
            FindEdit::Filter(needle) => {
                self.apply_local_filter(needle);
                FindNote::Filtered
            }
            FindEdit::Walk => FindNote::Walk,
        }
    }

    fn apply_local_filter(&mut self, needle: String) {
        let old = self
            .find
            .as_ref()
            .map(|find| find.needle.clone())
            .unwrap_or_default();
        if old != needle {
            self.selected = 0;
        }
        if let Some(find) = &mut self.find {
            find.stem = query_stem(&find.query);
            find.needle = needle;
            find.cycling = false;
            find.resolved = find.query.clone();
            find.landed = true;
        }
    }

    /// Tests walk immediately. The UI queues the walk instead.
    #[cfg(test)]
    fn find_push(&mut self, ch: char) {
        if self.edit_find_char(ch) == FindNote::Walk {
            self.apply_find();
        }
    }

    /// Tests walk immediately. The UI queues the walk instead.
    #[cfg(test)]
    fn find_pop(&mut self) {
        if self.edit_find_pop() == FindNote::Walk {
            self.apply_find();
        }
    }

    fn finish_walk(&mut self, walk: HostWalk) -> FindNote {
        if self.find.is_none() {
            return FindNote::Unchanged;
        }
        let cwd_changed = self.cwd != walk.cwd;
        if walk.error.is_empty() {
            self.entries = walk.entries;
        } else {
            self.error = walk.error;
            if cwd_changed {
                self.entries.clear();
            }
        }
        if cwd_changed {
            self.cwd = walk.cwd;
            self.selected = 0;
        } else if self.selected >= self.entries.len() {
            self.selected = self.entries.len().saturating_sub(1);
        }
        let Some(find) = &self.find else {
            return FindNote::Unchanged;
        };
        let current = find.query.clone();
        let old_needle = find.needle.clone();
        let (needle, resolved, landed, note) =
            settle_find_query(&current, &walk.query, walk.needle, walk.landed);
        if old_needle != needle {
            self.selected = 0;
        }
        if let Some(find) = &mut self.find {
            find.needle = needle;
            find.stem = query_stem(&find.query);
            find.cycling = false;
            find.resolved = resolved;
            find.landed = landed;
        }
        note
    }

    /// Tests walk immediately. The UI queues the walk instead.
    #[cfg(test)]
    fn apply_find(&mut self) {
        let (anchor, query, old_needle) = {
            let Some(find) = &self.find else {
                return;
            };
            (find.anchor.clone(), find.query.clone(), find.needle.clone())
        };
        let walked = follow_path(&anchor, &query);
        let cwd_changed = self.cwd != walked.cwd;
        if cwd_changed {
            self.cwd = walked.cwd;
            self.reload();
        }
        if cwd_changed || old_needle != walked.needle {
            self.selected = 0;
        }
        if let Some(find) = &mut self.find {
            find.needle = walked.needle;
            find.stem = query_stem(&query);
            find.cycling = false;
            find.resolved = query;
            find.landed = walked.landed;
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

fn suggested_public_path(tag: &str) -> String {
    let name = format!("{tag}.pub");
    match user_home() {
        Some(home) => home.join(name).display().to_string(),
        None => name,
    }
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
    let block = shell(" Get ", surface());
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
    frame.render_widget(Paragraph::new(lines).style(surface()), inner);
}

struct HealthView {
    stage: String,
    done: u64,
    total: u64,
    report: Option<HealthReport>,
    error: Option<String>,
}

fn draw_health(frame: &mut Frame, view: &HealthView, running: bool) {
    paint_screen(frame);
    let [header, body, help] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    paint_banner(frame, header, "Health", "bitrot check");
    if running {
        let ratio = if view.total == 0 {
            1.0
        } else {
            (view.done as f64 / view.total as f64).clamp(0.0, 1.0)
        };
        draw_meter(
            frame,
            body,
            "Checking",
            &view.stage,
            "Damaged blocks are rewritten on the volume.",
            ratio,
            &format!("{} / {} blocks", view.done, view.total),
        );
    } else {
        draw_health_result(frame, body, view);
    }
    let keys: &[(&str, &str)] = if running {
        &[("esc", "cancel"), ("q", "cancel"), ("ctrl-c", "cancel")]
    } else {
        &[("enter", "close"), ("esc", "close"), ("q", "close")]
    };
    frame.render_widget(Paragraph::new(keymap(keys)).style(chrome(false)), help);
}

fn draw_health_result(frame: &mut Frame, area: Rect, view: &HealthView) {
    let area = dialog_area(area, 68, 12);
    let block = shell(" Report ", surface()).padding(Padding::horizontal(2));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.is_empty() {
        return;
    }
    let lines = if let Some(err) = &view.error {
        vec![
            Line::from(Span::styled(
                "The check stopped.",
                fg(TEXT).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(err.clone(), fg(BAD))),
        ]
    } else if let Some(report) = &view.report {
        let unrepairable_style = if report.unrepairable > 0 {
            fg(BAD)
        } else {
            fg(SAGE)
        };
        vec![
            Line::from(Span::styled(
                "Check finished.",
                fg(TEXT).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("checked       {}", report.checked_blocks),
                fg(TEXT),
            )),
            Line::from(Span::styled(
                format!("repaired      {}", report.repaired_blocks),
                fg(TEXT),
            )),
            Line::from(Span::styled(
                format!("unrepairable  {}", report.unrepairable),
                unrepairable_style,
            )),
        ]
    } else {
        vec![Line::from(Span::styled("No report.", fg(MUTED)))]
    };
    frame.render_widget(
        Paragraph::new(lines)
            .style(surface())
            .wrap(Wrap { trim: false }),
        inner,
    );
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

static RESUME: AtomicBool = AtomicBool::new(false);
static TERMIOS_READY: AtomicBool = AtomicBool::new(false);
static mut SAVED_TERMIOS: libc::termios = unsafe { std::mem::zeroed() };

fn save_termios() {
    unsafe {
        let mut termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut termios) == 0 {
            SAVED_TERMIOS = termios;
            TERMIOS_READY.store(true, Ordering::Release);
        }
    }
}

fn install_job_signals() {
    unsafe {
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_sigtstp as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGTSTP, &action, std::ptr::null_mut());
    }
}

extern "C" fn on_sigtstp(_sig: libc::c_int) {
    const LEAVE: &[u8] =
        b"\x1b[?1049l\x1b[0m\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l";
    unsafe {
        libc::write(
            libc::STDOUT_FILENO,
            LEAVE.as_ptr() as *const libc::c_void,
            LEAVE.len(),
        );
        if TERMIOS_READY.load(Ordering::Relaxed) {
            libc::tcsetattr(
                libc::STDIN_FILENO,
                libc::TCSANOW,
                std::ptr::addr_of!(SAVED_TERMIOS),
            );
        }
        // The handler mask blocks SIGTSTP. raise cannot stop the process until
        // that bit is clear, and the disposition has to be the default or the
        // handler runs again instead of suspending.
        libc::signal(libc::SIGTSTP, libc::SIG_DFL);
        let mut unblock = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut unblock);
        libc::sigaddset(&mut unblock, libc::SIGTSTP);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
        libc::raise(libc::SIGTSTP);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_sigtstp as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGTSTP, &action, std::ptr::null_mut());
        RESUME.store(true, Ordering::Relaxed);
    }
}

fn block_stop_signal() {
    adjust_stop_signal(libc::SIG_BLOCK);
}

fn unblock_stop_signal() {
    adjust_stop_signal(libc::SIG_UNBLOCK);
}

fn adjust_stop_signal(how: libc::c_int) {
    unsafe {
        let mut set = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTSTP);
        libc::pthread_sigmask(how, &set, std::ptr::null_mut());
    }
}

fn claim_foreground() {
    if !io::stdin().is_terminal() {
        return;
    }
    let group = unsafe { libc::getpgrp() };
    crate::ssh::set_foreground_group(group);
}

fn take_resume() -> bool {
    RESUME.swap(false, Ordering::Relaxed)
}

fn next_event(timeout_ms: u64) -> Result<Option<Event>> {
    let mut tty_errors = 0u8;
    loop {
        if RESUME.load(Ordering::Relaxed) {
            return Ok(None);
        }
        match event::poll(Duration::from_millis(timeout_ms)) {
            Ok(false) => return Ok(None),
            Ok(true) => match event::read() {
                Ok(event) => return Ok(Some(event)),
                Err(err) if interrupted(&err) => continue,
                Err(err) if tty_lost(&err) => {
                    tty_errors = tty_errors.saturating_add(1);
                    if tty_errors > 20 {
                        return Err(err.into());
                    }
                    claim_foreground();
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => return Err(err.into()),
            },
            Err(err) if interrupted(&err) => continue,
            Err(err) if tty_lost(&err) => {
                tty_errors = tty_errors.saturating_add(1);
                if tty_errors > 20 {
                    return Err(err.into());
                }
                claim_foreground();
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

fn tty_lost(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EIO)
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
            let background = text_bg(buffer, "/dev/sda");
            assert_eq!(
                background,
                INK,
                "password dialog background\n{}",
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

    fn followed(anchor: &Path, query: &str) -> (PathBuf, String) {
        let walked = follow_path(anchor, query);
        (walked.cwd, walked.needle)
    }

    #[test]
    fn follow_path_enters_on_a_trailing_slash() {
        let tmp = Tmp::new();
        let dir1 = tmp.path.join("dir1");
        let dir2 = dir1.join("dir2");
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(dir1.join("file.txt"), "x").unwrap();
        std::os::unix::fs::symlink(&dir1, tmp.path.join("linkdir")).unwrap();

        let (cwd, needle) = followed(&tmp.path, "dir1");
        assert_eq!((cwd, needle), (tmp.path.clone(), "dir1".to_string()));

        let (cwd, needle) = followed(&tmp.path, "dir1/");
        assert_eq!((cwd, needle), (dir1.clone(), String::new()));

        let (cwd, needle) = followed(&tmp.path, "dir1/dir2");
        assert_eq!((cwd, needle), (dir1.clone(), "dir2".to_string()));

        let (cwd, needle) = followed(&tmp.path, "dir1/dir2/");
        assert_eq!((cwd, needle), (dir2.clone(), String::new()));

        let (cwd, needle) = followed(&tmp.path, "missing/");
        assert_eq!((cwd, needle), (tmp.path.clone(), "missing".to_string()));

        let (cwd, needle) = followed(&tmp.path, "dir1/file.txt/nope");
        assert_eq!((cwd, needle), (dir1.clone(), "file.txt".to_string()));

        let (cwd, needle) = followed(&dir2, "../");
        assert_eq!((cwd, needle), (dir1.clone(), String::new()));

        let (cwd, needle) = followed(&tmp.path, "./dir1/");
        assert_eq!((cwd, needle), (dir1, String::new()));

        let link = tmp.path.join("linkdir");
        let (cwd, needle) = followed(&tmp.path, "linkdir/");
        assert_eq!((cwd, needle), (link, String::new()));

        let absolute = format!("{}/", dir2.display());
        let (cwd, needle) = followed(&tmp.path, &absolute);
        assert_eq!((cwd, needle), (dir2, String::new()));

        let (cwd, needle) = followed(&tmp.path, "/");
        assert_eq!((cwd, needle), (PathBuf::from("/"), String::new()));

        assert!(follow_path(&tmp.path, "dir1/").landed);
        assert!(!follow_path(&tmp.path, "missing/").landed);
        assert!(!follow_path(&tmp.path, "dir1/file.txt/nope").landed);
    }

    #[test]
    fn find_edit_lists_only_when_the_directory_changes() {
        let filter =
            |resolved: &str, landed: bool, query: &str| match find_edit(resolved, landed, query) {
                FindEdit::Filter(needle) => needle,
                FindEdit::Walk => panic!("{query} walked"),
            };
        assert_eq!(filter("", true, "dir"), "dir");
        assert_eq!(filter("dir", true, "dir1"), "dir1");
        assert_eq!(filter("dir1/", true, "dir1/n"), "n");
        assert_eq!(filter("dir1/n", true, "dir1/"), "");
        assert_eq!(filter("/", true, "/a"), "a");
        assert!(matches!(find_edit("dir1", true, "dir1/"), FindEdit::Walk));
        assert!(matches!(find_edit("dir1/", true, "dir1"), FindEdit::Walk));
        assert!(matches!(find_edit("", true, "/"), FindEdit::Walk));
        assert!(matches!(
            find_edit("missing/x", false, "missing/xy"),
            FindEdit::Walk
        ));
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
    fn host_find_filters_without_listing_and_defers_the_walk() {
        let tmp = Tmp::new();
        let dir1 = tmp.path.join("dir1");
        std::fs::create_dir(&dir1).unwrap();
        std::fs::write(dir1.join("notes.txt"), "n").unwrap();
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
        std::fs::create_dir(tmp.path.join("late")).unwrap();
        host.begin_find();
        for ch in "dir1".chars() {
            assert_eq!(host.edit_find_char(ch), FindNote::Filtered);
        }
        assert_eq!(host.cwd, tmp.path);
        assert_eq!(host.find.as_ref().unwrap().needle, "dir1");
        assert!(host.entries.iter().all(|entry| entry.name != "late"));
        assert_eq!(host.edit_find_char('/'), FindNote::Walk);
        assert_eq!(host.cwd, tmp.path);
        assert!(host.entries.iter().all(|entry| entry.name != "late"));
        host.apply_find();
        assert_eq!(host.cwd, dir1);
        assert!(host.find.as_ref().unwrap().landed);
        std::fs::write(dir1.join("other.txt"), "o").unwrap();
        assert_eq!(host.edit_find_char('n'), FindNote::Filtered);
        assert_eq!(host.cwd, dir1);
        assert_eq!(host.find.as_ref().unwrap().needle, "n");
        assert_eq!(shown_names(&host), vec!["notes.txt".to_string()]);

        host.end_find(true);
        host.begin_find();
        for ch in "dir1/".chars() {
            host.edit_find_char(ch);
        }
        assert_eq!(host.edit_find_char('n'), FindNote::Walk);
        assert_eq!(host.cwd, tmp.path);
        let note = host.finish_walk(HostWalk {
            query: "dir1/".into(),
            cwd: dir1.clone(),
            entries: list_host_dir(&dir1).unwrap(),
            needle: String::new(),
            landed: true,
            error: String::new(),
        });
        assert_eq!(note, FindNote::Filtered);
        assert_eq!(host.cwd, dir1);
        assert_eq!(host.find.as_ref().unwrap().query, "dir1/n");
        assert_eq!(host.find.as_ref().unwrap().needle, "n");
        assert_eq!(shown_names(&host), vec!["notes.txt".to_string()]);
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
                resolved: "/not".into(),
                landed: true,
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
                resolved: "zzz".into(),
                landed: true,
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
    fn disk_list_i_initializes_the_highlighted_drive() {
        let tmp = Tmp::new();
        let missing = tmp.path.join("missing.img");
        let magic = tmp.path.join("magic.img");
        std::fs::write(&magic, b"HDNFS2\0\0").unwrap();

        let mut app = pick_app(vec![fake_disk(&missing), fake_disk(&magic)], 1);
        app.on_pick(repeat_key('i')).unwrap();
        assert!(matches!(app.screen, Screen::Pick(_)));

        app.on_pick(press_key('i')).unwrap();
        match &app.screen {
            Screen::Setup(setup) => {
                assert_eq!(setup.path, magic);
                assert!(setup.fields.contains(&FieldId::Confirm));
                assert!(setup.confirm.is_empty());
                assert!(setup.size.is_empty());
            }
            _ => panic!("i should open init"),
        }
        assert!(!app.setup_command(repeat_key('i')));
        match &app.screen {
            Screen::Setup(setup) => assert!(setup.confirm.is_empty()),
            _ => panic!("repeat should stay on the empty form"),
        }
        assert!(!app.setup_command(press_key('i')));
        match &app.screen {
            Screen::Setup(setup) => assert_eq!(setup.confirm, "i"),
            _ => panic!("a later press should type"),
        }

        let mut open = pick_app(vec![fake_disk(&magic)], 0);
        open.on_pick(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(open.screen, Screen::Unlock(ref unlock) if unlock.path == magic));

        let mut fresh = pick_app(vec![fake_disk(&missing)], 0);
        fresh.on_pick(press_key('i')).unwrap();
        match &fresh.screen {
            Screen::Setup(setup) => {
                assert_eq!(setup.path, missing);
                assert!(!setup.fields.contains(&FieldId::Confirm));
                assert!(setup.size.is_empty());
            }
            _ => panic!("missing path should open init"),
        }
        assert!(!fresh.setup_command(repeat_key('i')));
        match &fresh.screen {
            Screen::Setup(setup) => assert!(setup.size.is_empty()),
            _ => panic!("repeat should leave size empty"),
        }

        let mut typing = pick_app(vec![fake_disk(&magic)], 0);
        if let Screen::Pick(pick) = &mut typing.screen {
            pick.editing = true;
            pick.path = "/dev/".into();
        }
        typing.on_pick(press_key('i')).unwrap();
        match &typing.screen {
            Screen::Pick(pick) => {
                assert!(pick.editing);
                assert_eq!(pick.path, "/dev/i");
            }
            _ => panic!("editing should take the character"),
        }

        let mut empty = pick_app(vec![], 0);
        empty.on_pick(press_key('i')).unwrap();
        assert!(matches!(empty.screen, Screen::Pick(ref pick) if pick.disks.is_empty()));

        let mut sudo = pick_app(vec![], 0);
        sudo.screen = Screen::Sudo(Sudo {
            path: magic.clone(),
            password: Hidden::default(),
            after: AfterAccess::Initialize,
        });
        sudo.ignore_repeat = Some(KeyCode::Char('i'));
        sudo.on_sudo(repeat_key('i')).unwrap();
        match &sudo.screen {
            Screen::Sudo(prompt) => {
                assert_eq!(prompt.after, AfterAccess::Initialize);
                assert!(prompt.password.expose().is_empty());
            }
            _ => panic!("repeat should stay on sudo"),
        }
        sudo.on_sudo(press_key('a')).unwrap();
        match &sudo.screen {
            Screen::Sudo(prompt) => assert_eq!(prompt.password.expose(), "a"),
            _ => panic!("sudo should then take a character"),
        }
    }

    struct JobHold {
        release: Option<mpsc::Sender<()>>,
    }

    impl JobHold {
        fn arm() -> Self {
            let (tx, rx) = mpsc::channel();
            INLINE_JOBS.with(|cell| cell.set(false));
            JOB_HOLD.with(|cell| cell.set(Some(rx)));
            Self { release: Some(tx) }
        }
    }

    impl Drop for JobHold {
        fn drop(&mut self) {
            INLINE_JOBS.with(|cell| cell.set(true));
            if let Some(tx) = self.release.take() {
                let _ = tx.send(());
            }
        }
    }

    fn press_key(ch: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)
    }

    fn repeat_key(ch: char) -> KeyEvent {
        KeyEvent::new_with_kind(KeyCode::Char(ch), KeyModifiers::NONE, KeyEventKind::Repeat)
    }

    fn fake_disk(path: &Path) -> Disk {
        Disk {
            path: path.display().to_string(),
            bytes: 1024,
            model: "test".into(),
            removable: false,
            partition: false,
            file: false,
        }
    }

    fn pick_app(disks: Vec<Disk>, selected: usize) -> App {
        App {
            screen: Screen::Pick(Pick {
                disks,
                selected,
                editing: false,
                path: String::new(),
            }),
            ignore_repeat: None,
            job: None,
            alert: None,
            pending_ssh: None,
            dial: None,
            last_frame: RefCell::new(None),
        }
    }

    #[test]
    fn opening_a_disk_paints_and_cancels_without_blocking_the_screen() {
        let _hold = JobHold::arm();
        let tmp = Tmp::new();
        let volume = tmp.path.join("vault.img");
        std::fs::write(&volume, b"HDNFS2\0\0").unwrap();
        let mut app = pick_app(vec![fake_disk(&volume)], 0);
        app.on_pick(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(app.screen, Screen::Pick(_)));
        let job = app.job.as_ref().expect("open stays in the background");
        assert_eq!(job.title, "Opening");
        assert!(job.detail.contains("vault.img"), "{}", job.detail);
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(!view.contains("Opening"), "{view}");
        assert!(view.contains("vault.img"), "{view}");
        app.job.as_mut().unwrap().started -= JOB_CURTAIN;
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("Devices"), "{view}");
        assert!(view.contains("vault.img"), "{view}");
        assert!(!view.contains("Esc leaves this screen"), "{view}");
        let buffer = terminal.backend().buffer();
        let help = row_text(buffer, buffer.area.height - 2);
        let bar = row_text(buffer, buffer.area.height - 1);
        assert!(bar.chars().any(|ch| LOADER_FRAMES.contains(&ch)), "{bar}");
        assert!(bar.contains("Opening"), "{bar}");
        assert!(bar.contains("vault.img"), "{bar}");
        assert!(
            bar.split_whitespace()
                .any(|word| word.ends_with('s') && word.chars().any(|ch| ch.is_ascii_digit())),
            "{bar}"
        );
        assert!(help.contains("esc") && help.contains("cancel"), "{help}");
        assert!(!help.contains("init"), "{help}");
        let previous = std::mem::replace(&mut app.screen, Screen::Parked);
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("Devices"), "{view}");
        assert!(view.contains("Disks"), "{view}");
        let buffer = terminal.backend().buffer();
        let bar = row_text(buffer, buffer.area.height - 1);
        assert!(bar.contains("Opening"), "{bar}");
        app.screen = previous;
        app.cancel_job(2);
        assert!(app.job.is_none());
        assert!(matches!(app.screen, Screen::Pick(_)));
    }

    #[test]
    fn disk_rows_keep_their_columns_when_a_name_is_long() {
        let short = Disk {
            path: "/dev/sda".into(),
            bytes: 1024,
            model: "PS8".into(),
            removable: true,
            partition: false,
            file: false,
        };
        let long = Disk {
            path: "/dev/mapper/luks-0123456789abcdef-very-long-name".into(),
            bytes: 4096,
            model: "WD_BLACK SN770 250GB extra label".into(),
            removable: true,
            partition: false,
            file: false,
        };
        let disks = vec![short, long];
        let widths = disk_widths(&disks, 64);
        let left = line_plain(&disk_row(&disks[0], &widths));
        let right = line_plain(&disk_row(&disks[1], &widths));
        assert_eq!(
            left.chars().count(),
            right.chars().count(),
            "{left}\n{right}"
        );
        assert!(left.chars().count() <= 64, "{left}");
        assert_eq!(
            column_of(&left, "1.0 K"),
            column_of(&right, "4.0 K"),
            "{left}\n{right}"
        );
        assert_eq!(
            column_of(&left, "disk"),
            column_of(&right, "disk"),
            "{left}\n{right}"
        );
        assert_eq!(
            column_of(&left, "removable"),
            column_of(&right, "removable"),
            "{left}\n{right}"
        );
        assert!(right.contains('…'), "{right}");
        assert!(right.contains("long-name"), "{right}");
        assert!(right.contains("WD_BLACK"), "{right}");
    }

    fn column_of(row: &str, label: &str) -> usize {
        let byte = row
            .find(label)
            .unwrap_or_else(|| panic!("{label} missing in {row}"));
        row[..byte].chars().count()
    }

    fn line_plain(line: &Line<'_>) -> String {
        line.spans.iter().map(|span| span.content.clone()).collect()
    }

    #[test]
    fn disk_list_uses_dev_paths() {
        for disk in list_disks() {
            assert!(disk.path.starts_with("/dev/"), "{}", disk.path);
            assert!(disk.bytes > 0, "{}", disk.path);
            assert!(!disk.file, "{}", disk.path);
        }
    }

    #[test]
    fn volume_files_are_magic_files_in_one_directory() {
        let tmp = Tmp::new();
        let volume = tmp.path.join("vault.img");
        let nested_dir = tmp.path.join("nested");
        std::fs::write(&volume, b"HDNFS2\0\0").unwrap();
        std::fs::write(tmp.path.join("notes.txt"), b"HDNFS2 is text").unwrap();
        std::fs::write(tmp.path.join("empty.img"), b"").unwrap();
        std::fs::create_dir(&nested_dir).unwrap();
        std::fs::write(nested_dir.join("hidden.img"), b"HDNFS2\0\0").unwrap();
        std::os::unix::fs::symlink(&volume, tmp.path.join("link.img")).unwrap();

        let found = list_volume_files(&tmp.path);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, volume.display().to_string());
        assert!(found[0].file);
        assert_eq!(found[0].bytes, 8);
        assert!(!found[0].partition);

        for disk in list_pick_entries() {
            if disk.file {
                let path = PathBuf::from(&disk.path);
                assert!(path.is_file(), "{}", disk.path);
                assert!(has_volume_magic(&path).unwrap(), "{}", disk.path);
            } else {
                assert!(disk.path.starts_with("/dev/"), "{}", disk.path);
            }
        }
    }

    #[test]
    fn n_initializes_a_new_file_with_the_init_form() {
        let tmp = Tmp::new();
        let missing = tmp.path.join("fresh.img");
        let existing = tmp.path.join("vault.img");
        std::fs::write(&existing, b"HDNFS2\0\0").unwrap();

        let mut app = pick_app(vec![], 0);
        app.on_pick(press_key('n')).unwrap();
        let prefix = match &app.screen {
            Screen::Setup(setup) => {
                assert_eq!(
                    setup.fields,
                    vec![
                        FieldId::Path,
                        FieldId::Size,
                        FieldId::Password,
                        FieldId::Again
                    ]
                );
                assert_eq!(setup.cursor, 0);
                assert!(setup.path_text.ends_with('/'), "{}", setup.path_text);
                assert!(!setup.block);
                setup.path_text.clone()
            }
            _ => panic!("n should open the init form"),
        };
        press_setup(&mut app, repeat_key('n'));
        match &app.screen {
            Screen::Setup(setup) => assert_eq!(setup.path_text, prefix),
            _ => panic!("a repeat should not type into the path"),
        }
        press_setup(&mut app, press_key('a'));
        match &app.screen {
            Screen::Setup(setup) => assert_eq!(setup.path_text, format!("{prefix}a")),
            _ => panic!("the path field should take the character"),
        }

        match &mut app.screen {
            Screen::Setup(setup) => setup.path_text = missing.display().to_string(),
            _ => unreachable!(),
        }
        press_setup(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Setup(setup) => {
                assert_eq!(setup.path, missing);
                assert!(!setup.block);
                assert!(setup.capacity.is_none());
                assert!(!setup.fields.contains(&FieldId::Confirm));
            }
            _ => panic!("a new file should stay on the init form"),
        }
        assert_eq!(
            app.alert.as_deref(),
            Some("password must be at least 12 characters")
        );

        let mut again = pick_app(vec![], 0);
        again.on_pick(press_key('n')).unwrap();
        match &mut again.screen {
            Screen::Setup(setup) => setup.path_text = existing.display().to_string(),
            _ => panic!("n should open the init form"),
        }
        press_setup(
            &mut again,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        match &again.screen {
            Screen::Setup(setup) => {
                assert_eq!(setup.path, existing);
                assert!(!setup.block);
                assert_eq!(setup.active(), FieldId::Confirm);
                assert_eq!(
                    setup.fields,
                    vec![
                        FieldId::Path,
                        FieldId::Confirm,
                        FieldId::Size,
                        FieldId::Password,
                        FieldId::Again
                    ]
                );
            }
            _ => panic!("an existing file should ask for the path again"),
        }
        assert_eq!(again.alert.as_deref(), Some("retype the path to confirm"));

        let mut directory = pick_app(vec![], 0);
        directory.on_pick(press_key('n')).unwrap();
        match &mut directory.screen {
            Screen::Setup(setup) => setup.path_text = tmp.path.display().to_string(),
            _ => panic!("n should open the init form"),
        }
        press_setup(
            &mut directory,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        assert_eq!(
            directory.alert.as_deref(),
            Some("volume path is not a file or a block device")
        );
        assert!(matches!(directory.screen, Screen::Setup(_)));

        let mut typing = pick_app(vec![], 0);
        typing.on_pick(press_key('/')).unwrap();
        typing.on_pick(press_key('n')).unwrap();
        match &typing.screen {
            Screen::Pick(pick) => {
                assert!(pick.editing);
                assert_eq!(pick.path, "/n");
            }
            _ => panic!("/ should keep the open path field"),
        }

        let file = Disk {
            path: existing.display().to_string(),
            bytes: 8,
            model: String::new(),
            removable: false,
            partition: false,
            file: true,
        };
        let mut listed = pick_app(vec![file, fake_disk(Path::new("/dev/sda"))], 0);
        assert_eq!(listed.detail(), "1 file, 1 disk");
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(120, 16)).unwrap();
        terminal.draw(|frame| listed.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("vault.img"), "{view}");
        assert!(view.contains("file"), "{view}");
        assert!(view.contains("n new"), "{view}");
        assert!(view.contains("c passwd"), "{view}");
        assert!(view.contains("/dev/sda"), "{view}");

        let mut narrow = Terminal::new(ratatui::backend::TestBackend::new(80, 16)).unwrap();
        narrow.draw(|frame| listed.draw(frame)).unwrap();
        let view = narrow.backend().to_string();
        assert!(view.contains("c passwd"), "{view}");
        assert!(view.contains("q quit"), "{view}");

        listed.on_pick(press_key('n')).unwrap();
        terminal.draw(|frame| listed.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("New volume"), "{view}");
        assert!(view.contains("Path"), "{view}");
        assert!(view.contains("Size"), "{view}");
        assert!(view.contains("initialize"), "{view}");
        assert!(!view.contains("Devices"), "{view}");
    }

    #[test]
    fn c_opens_the_password_form_from_the_drive_list() {
        let tmp = Tmp::new();
        let plain = tmp.path.join("notes.txt");
        std::fs::write(&plain, b"notes").unwrap();
        let mut app = pick_app(vec![fake_disk(&plain)], 0);
        app.on_pick(press_key('c')).unwrap();
        assert_eq!(app.alert.as_deref(), Some("not an hdnfs volume"));
        assert!(matches!(app.screen, Screen::Pick(_)));

        let missing = tmp.path.join("missing.img");
        let mut gone = pick_app(vec![fake_disk(&missing)], 0);
        gone.on_pick(press_key('c')).unwrap();
        assert_eq!(gone.alert.as_deref(), Some("not an hdnfs volume"));

        let mut typing = pick_app(vec![fake_disk(&plain)], 0);
        typing.on_pick(press_key('/')).unwrap();
        typing.on_pick(press_key('c')).unwrap();
        match &typing.screen {
            Screen::Pick(pick) => assert_eq!(pick.path, "/c"),
            _ => panic!("/ should keep the open path field"),
        }

        let mut empty = pick_app(vec![], 0);
        empty.on_pick(press_key('c')).unwrap();
        assert!(matches!(
            empty.screen,
            Screen::Pick(ref pick) if pick.disks.is_empty()
        ));
        assert!(empty.alert.is_none());

        let magic = tmp.path.join("magic.img");
        std::fs::write(&magic, b"HDNFS2\0\0").unwrap();
        let mut app = pick_app(vec![fake_disk(&magic)], 0);
        app.on_pick(repeat_key('c')).unwrap();
        assert!(matches!(app.screen, Screen::Pick(_)));
        app.on_pick(press_key('c')).unwrap();
        match &app.screen {
            Screen::Passwd(form) => {
                assert_eq!(form.path, magic);
                assert_eq!(form.cursor, 0);
                assert!(form.current.expose().is_empty());
            }
            _ => panic!("c should open the password form"),
        }
        app.on_passwd(repeat_key('c')).unwrap();
        match &app.screen {
            Screen::Passwd(form) => assert!(form.current.expose().is_empty()),
            _ => panic!("a repeat should not type"),
        }
        app.on_passwd(press_key('a')).unwrap();
        match &app.screen {
            Screen::Passwd(form) => assert_eq!(form.current.expose(), "a"),
            _ => panic!("the current field should take the character"),
        }
        app.on_passwd(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE))
            .unwrap();
        match &app.screen {
            Screen::Passwd(form) => assert_eq!(form.cursor, 1),
            _ => panic!("tab should move to the new password"),
        }

        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 16)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("Change password"), "{view}");
        assert!(view.contains("Current"), "{view}");
        assert!(view.contains("New"), "{view}");
        assert!(view.contains("Again"), "{view}");
        assert!(view.contains("change"), "{view}");

        set_passwd(
            &mut app,
            "correct horse battery",
            "battery horse correct",
            "nope nope nope!",
        );
        app.on_passwd(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert_eq!(app.alert.as_deref(), Some("passwords do not match"));
        match &app.screen {
            Screen::Passwd(form) => assert_eq!(form.current.expose(), "correct horse battery"),
            _ => panic!("a mismatch should stay on the form"),
        }

        set_passwd(&mut app, "correct horse battery", "short", "short");
        app.on_passwd(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert_eq!(
            app.alert.as_deref(),
            Some("password must be at least 12 characters")
        );
        match &app.screen {
            Screen::Passwd(form) => assert_eq!(form.next.expose(), "short"),
            _ => panic!("a short password should stay on the form"),
        }
    }

    #[test]
    fn c_changes_the_password_of_the_highlighted_volume() {
        let tmp = Tmp::new();
        let volume_path = tmp.path.join("vault.img");
        let password = "correct horse battery";
        let changed = "battery horse correct";
        init_volume(InitOptions {
            path: &volume_path,
            password,
            size: Some(64 * 1024 * 1024),
            force: false,
            kdf: KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            progress: None,
        })
        .unwrap();
        let host = tmp.path.join("note.txt");
        std::fs::write(&host, b"still-here").unwrap();
        {
            let mut volume = Volume::open(&volume_path, password, LockMode::Exclusive).unwrap();
            volume.put(&host, "/note").unwrap();
        }

        let mut app = pick_app(vec![fake_disk(&volume_path)], 0);
        app.on_pick(press_key('c')).unwrap();
        set_passwd(&mut app, "wrong password!", changed, changed);
        app.on_passwd(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert_eq!(
            app.alert.as_deref(),
            Some("wrong password or corrupted volume header")
        );
        match &app.screen {
            Screen::Passwd(form) => {
                assert!(form.current.expose().is_empty());
                assert!(form.next.expose().is_empty());
            }
            _ => panic!("a wrong password should stay on the form"),
        }

        set_passwd(&mut app, password, changed, changed);
        app.on_passwd(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert_eq!(app.alert.as_deref(), Some("password changed"));
        assert!(matches!(app.screen, Screen::Pick(_)));

        match Volume::open(&volume_path, password, LockMode::Exclusive) {
            Err(err) => assert_eq!(err.code(), "wrong_password"),
            Ok(_) => panic!("old password opened the volume"),
        }
        let mut volume = Volume::open(&volume_path, changed, LockMode::Exclusive).unwrap();
        let out = tmp.path.join("out.txt");
        volume.get("/note", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"still-here");
    }

    fn set_passwd(app: &mut App, current: &str, next: &str, again: &str) {
        {
            let Screen::Passwd(form) = &mut app.screen else {
                panic!("password form");
            };
            form.current = Hidden(current.to_string());
            form.next = Hidden(next.to_string());
            form.again = Hidden(again.to_string());
        }
        app.alert = None;
    }

    fn press_setup(app: &mut App, key: KeyEvent) {
        if app.setup_command(key) {
            app.submit_setup().unwrap();
        }
    }

    #[test]
    fn every_frame_paints_the_screen() {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(40, 12)).unwrap();
        let app = App::new();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("HDNFS"), "{view}");
        assert!(view.contains("i init"), "{view}");

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

    fn row_text(buffer: &ratatui::buffer::Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect()
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
    fn connecting_screen_shows_a_cancelable_loader() {
        let elapsed = std::time::Duration::from_secs(2);
        assert_eq!(loader_frame(elapsed), '⠴');
        assert_eq!(format_elapsed(elapsed), "2s");
        assert_eq!(format_elapsed(std::time::Duration::from_secs(61)), "1m01s");
        let tmp = Tmp::new();
        let volume = tmp.path.join("vault.img");
        std::fs::write(&volume, b"HDNFS2\0\0").unwrap();
        let app = pick_app(vec![fake_disk(&volume)], 0);
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        let loader = LoaderView {
            title: "Connecting".into(),
            detail: "prod".into(),
            elapsed,
        };
        terminal
            .draw(|frame| app.draw_screen(frame, Some(&loader)))
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("vault.img"), "{view}");
        assert!(view.contains("Devices"), "{view}");
        assert!(!view.contains("Waiting for authentication"), "{view}");
        let buffer = terminal.backend().buffer();
        let help = row_text(buffer, buffer.area.height - 2);
        let bar = row_text(buffer, buffer.area.height - 1);
        assert!(bar.contains('⠴'), "{bar}");
        assert!(bar.contains("2s"), "{bar}");
        assert!(bar.contains("Connecting"), "{bar}");
        assert!(bar.contains("prod"), "{bar}");
        assert!(
            (0..buffer.area.width).all(|x| buffer[(x, buffer.area.height - 1)].bg == RAISED),
            "{bar}"
        );
        assert!(help.contains("esc") && help.contains("cancel"), "{help}");
    }

    #[test]
    fn ssh_table_columns_share_header_starts() {
        let headers = ["tag", "target", "key"];
        let cells = host_cells(&crate::ssh::HostRow {
            tag: "prod".into(),
            target: "203.0.113.10".into(),
            key: "laptop".into(),
        });
        let widths = column_widths(&headers, std::slice::from_ref(&cells), 80);
        let header_cells: Vec<String> = headers.iter().map(|text| (*text).to_string()).collect();
        let header = format_columns(&header_cells, &widths);
        let row = format_columns(&cells, &widths);
        assert_eq!(header.find("target"), row.find("203"));
        assert_eq!(header.find("key"), row.find("laptop"));

        let key_headers = ["tag", "algorithm", "fingerprint", "comment"];
        let key = key_cells(&crate::ssh::KeyRow {
            tag: "laptop".into(),
            detail: crate::ssh::KeyDetail::Ready(crate::ssh::PublicInfo {
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:abc".into(),
                comment: "hdnfs".into(),
                line: String::new(),
            }),
        });
        let key_widths = column_widths(&key_headers, std::slice::from_ref(&key), 80);
        let key_header_cells: Vec<String> =
            key_headers.iter().map(|text| (*text).to_string()).collect();
        let key_header = format_columns(&key_header_cells, &key_widths);
        let key_row = format_columns(&key, &key_widths);
        assert_eq!(key_header.find("algorithm"), key_row.find("ssh-ed25519"));
        assert_eq!(key_header.find("fingerprint"), key_row.find("SHA256"));
        assert_eq!(key_header.find("comment"), key_row.find("hdnfs"));
        assert_eq!(
            key_cells(&crate::ssh::KeyRow {
                tag: "old".into(),
                detail: crate::ssh::KeyDetail::Incomplete,
            }),
            vec![
                "old".to_string(),
                "incomplete".into(),
                String::new(),
                String::new()
            ]
        );
    }

    #[test]
    fn files_view_lists_the_ssh_directory_and_hosts_screen() {
        let tmp = Tmp::new();
        let path = tmp.path.join("vol.img");
        hdnfs::init_volume(hdnfs::InitOptions {
            path: &path,
            password: "correct horse battery",
            size: Some(256 * 1024 * 1024),
            force: false,
            kdf: hdnfs::KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            progress: None,
        })
        .unwrap();
        let volume = Volume::open(&path, "correct horse battery", LockMode::Exclusive).unwrap();
        let mut app = App {
            screen: Screen::Browse(Browse::open(path, volume).unwrap()),
            ignore_repeat: None,
            job: None,
            alert: None,
            pending_ssh: None,
            dial: None,
            last_frame: RefCell::new(None),
        };

        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("menu"), "{view}");
        assert!(view.contains("m menu"), "{view}");
        assert!(view.contains("d delete"), "{view}");
        assert!(view.contains("b health"), "{view}");
        assert!(view.contains("w backup"), "{view}");
        assert!(view.contains("q quit"), "{view}");
        assert!(!view.contains("m hosts"), "{view}");

        assert!(matches!(app.react(press_key('m')), Apply::Stay));
        app.react(repeat_key('m'));
        match &app.screen {
            Screen::Browse(browse) => {
                assert!(browse.menu.open);
                assert_eq!(browse.view, BrowseView::Files);
                assert_eq!(browse.menu.cursor, 0);
            }
            _ => panic!("m should open the menu"),
        }
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        let buffer = terminal.backend().buffer();
        assert!(menu_item_highlighted(buffer, "files"), "{view}");
        assert!(!menu_item_highlighted(buffer, "hosts"), "{view}");
        assert_eq!(text_bg(buffer, "hosts"), INK, "menu background\n{view}");
        assert!(
            (0..buffer.area.height).any(|y| row_text(buffer, y).contains("keys")),
            "{view}"
        );
        assert!(
            (0..buffer.area.height).any(|y| row_text(buffer, y).contains("passwords")),
            "{view}"
        );
        app.react(press_key('j'));
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        let buffer = terminal.backend().buffer();
        assert!(menu_item_highlighted(buffer, "hosts"), "{view}");
        assert!(!menu_item_highlighted(buffer, "files"), "{view}");
        app.react(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        app.react(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.react(press_key('k'));
        match &app.screen {
            Screen::Browse(browse) => assert_eq!(browse.menu.cursor, 0),
            _ => panic!("k should return to files"),
        }
        app.react(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => {
                assert!(!browse.menu.open);
                assert_eq!(browse.view, BrowseView::Files);
            }
            _ => panic!("esc should close the menu"),
        }
        choose_menu(&mut app, BrowseView::Hosts);
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        assert!(view.contains("No hosts."), "{view}");
        assert!(view.contains("target"), "{view}");
        assert!(view.contains("m menu"), "{view}");
        assert!(view.contains("e edit"), "{view}");
        assert!(!view.contains("w backup"), "{view}");
        assert!(!view.contains("s keys"), "{view}");

        choose_menu(&mut app, BrowseView::Keys);
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        assert!(view.contains("No keys."), "{view}");
        assert!(view.contains("g public"), "{view}");
        app.react(press_key('g'));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { body, .. } => assert!(body.contains("nothing selected"), "{body}"),
                _ => panic!("g with no key should explain that"),
            },
            _ => panic!("g with no key should stay on the key list"),
        }
        app.react(press_key('x'));
        app.react(press_key('n'));
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("New key"), "{view}");
        assert!(view.contains("tag"), "{view}");
        assert!(view.contains("save"), "{view}");
        assert!(!view.contains("No keys."), "{view}");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::PageForm(form) => {
                    assert!(form.error.contains("tag"), "{}", form.error);
                    assert_eq!(form.cursor, 0);
                }
                _ => panic!("an empty tag should stay on the form"),
            },
            _ => panic!("an empty tag should stay on the form"),
        }
        type_text(&mut app, "laptop");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => {
                assert!(matches!(browse.prompt, Prompt::None));
                assert_eq!(browse.ssh.pane, SshPane::Keys);
                assert_eq!(browse.ssh.keys.len(), 1);
                assert!(
                    crate::ssh::format_key_row(&browse.ssh.keys[0]).contains("ed25519"),
                    "{}",
                    crate::ssh::format_key_row(&browse.ssh.keys[0])
                );
            }
            _ => panic!("created key should return to the key list"),
        }
        app.react(press_key('i'));
        let public_line = match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { body, .. } => {
                    assert!(body.contains("ssh-ed25519 "), "{body}");
                    assert!(body.contains("hdnfs:laptop"), "{body}");
                    body.lines()
                        .find_map(|line| line.strip_prefix("public: "))
                        .expect("public line")
                        .to_string()
                }
                _ => panic!("i should show the public key"),
            },
            _ => panic!("i should show the public key"),
        };
        app.react(press_key('x'));

        let dest = tmp.path.join("laptop.pub");
        app.react(press_key('g'));
        let prefilled = match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Line { title, value } => {
                    assert_eq!(*title, "public key path");
                    assert!(
                        value.ends_with("/laptop.pub") || value == "laptop.pub",
                        "{value}"
                    );
                    value.clone()
                }
                _ => panic!("g should ask for a path"),
            },
            _ => panic!("g should stay on the key list"),
        };
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("public key path"), "{view}");
        app.react(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!dest.exists());
        assert!(matches!(
            &app.screen,
            Screen::Browse(browse) if matches!(browse.prompt, Prompt::None)
        ));

        app.react(press_key('g'));
        for _ in 0..prefilled.chars().count() {
            app.react(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        }
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { title, body } => {
                    assert_eq!(title, "public key");
                    assert_eq!(body, "empty input");
                }
                _ => panic!("an empty path should be rejected"),
            },
            _ => panic!("an empty path should stay on the key list"),
        }
        app.react(press_key('x'));

        app.react(press_key('g'));
        for _ in 0..prefilled.chars().count() {
            app.react(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        }
        type_text(&mut app, &dest.display().to_string());
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { title, body } => {
                    assert_eq!(title, "public key");
                    assert!(body.contains(&dest.display().to_string()), "{body}");
                }
                _ => panic!("g should write the public key"),
            },
            _ => panic!("g should write the public key"),
        }
        let written = std::fs::read_to_string(&dest).unwrap();
        assert_eq!(written, format!("{public_line}\n"));
        assert!(!written.contains("PRIVATE KEY"));
        app.react(press_key('x'));

        app.react(press_key('g'));
        for _ in 0..prefilled.chars().count() {
            app.react(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        }
        type_text(&mut app, &dest.display().to_string());
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { body, .. } => assert!(body.contains("already exists"), "{body}"),
                _ => panic!("an existing path should be refused"),
            },
            _ => panic!("an existing path should stay on the key list"),
        }
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), written);
        app.react(press_key('x'));

        let imported = tmp.path.join("imported.pem");
        let generated =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let pem = generated.to_openssh(ssh_key::LineEnding::LF).unwrap();
        std::fs::write(&imported, pem.as_bytes()).unwrap();
        app.react(press_key('a'));
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        assert!(view.contains("Add key"), "{view}");
        assert!(view.contains("file"), "{view}");
        type_text(&mut app, "imported");
        down(&mut app);
        type_text(&mut app, &imported.display().to_string());
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => {
                assert!(matches!(browse.prompt, Prompt::None));
                assert_eq!(browse.ssh.keys.len(), 2);
            }
            _ => panic!("added key should return to the key list"),
        }

        choose_menu(&mut app, BrowseView::Hosts);
        match &app.screen {
            Screen::Browse(browse) => {
                assert_eq!(browse.ssh.pane, SshPane::Hosts);
                assert_eq!(browse.ssh.selected, 0);
            }
            _ => panic!("menu should return to hosts"),
        }
        app.react(press_key('n'));
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("New host"), "{view}");
        assert!(view.contains("hostname"), "{view}");
        assert!(view.contains("option"), "{view}");
        assert!(view.contains("save"), "{view}");
        assert!(!view.contains("No hosts."), "{view}");
        type_text(&mut app, "prod");
        down(&mut app);
        type_text(&mut app, "laptop");
        down(&mut app);
        type_text(&mut app, "203.0.113.10");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => {
                assert!(matches!(browse.prompt, Prompt::None));
                assert_eq!(browse.ssh.hosts.len(), 1);
                assert_eq!(
                    crate::ssh::format_host_row(&browse.ssh.hosts[0]),
                    "prod  203.0.113.10  laptop"
                );
            }
            _ => panic!("created host should return to the host list"),
        }
        app.react(press_key('e'));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::HostEdit(editor) => {
                    assert!(!editor.create);
                    assert_eq!(editor.tag, "prod");
                    assert_eq!(editor.key, "laptop");
                    assert_eq!(editor.hostname, "203.0.113.10");
                    assert_eq!(editor.cursor, 0);
                }
                _ => panic!("e should open the host form"),
            },
            _ => panic!("e should open the host form"),
        }
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("hostname"), "{view}");
        assert!(view.contains("203.0.113.10"), "{view}");
        assert!(view.contains("save"), "{view}");
        app.react(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        for _ in 0.."203.0.113.10".len() {
            app.react(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        }
        type_text(&mut app, "203.0.113.11");
        app.react(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.react(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.react(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        type_text(&mut app, "10");
        app.react(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        type_text(&mut app, "ServerAliveInterval 30");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => {
                assert!(matches!(browse.prompt, Prompt::None));
                assert_eq!(
                    crate::ssh::format_host_row(&browse.ssh.hosts[0]),
                    "prod  203.0.113.11  laptop"
                );
            }
            _ => panic!("edited host should return to the host list"),
        }
        app.react(press_key('i'));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { body, .. } => {
                    assert!(body.contains("203.0.113.11"), "{body}");
                    assert!(body.contains("timeout: 10"), "{body}");
                    assert!(body.contains("ConnectTimeout 10"), "{body}");
                    assert!(body.contains("ServerAliveInterval 30"), "{body}");
                }
                _ => panic!("i should show the edited host"),
            },
            _ => panic!("i should show the edited host"),
        }
        app.react(press_key('x'));
        match app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)) {
            Apply::Connect(tag) => assert_eq!(tag, "prod"),
            _ => panic!("enter should connect"),
        }

        app.react(press_key('d'));
        type_text(&mut app, "nope");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { body, .. } => {
                    assert!(body.contains("did not match"), "{body}");
                }
                _ => panic!("a mismatched tag should not delete"),
            },
            _ => panic!("a mismatched tag should not delete"),
        }
        app.react(press_key('x'));
        match &app.screen {
            Screen::Browse(browse) => assert_eq!(browse.ssh.hosts.len(), 1),
            _ => panic!("host should remain"),
        }

        choose_menu(&mut app, BrowseView::Keys);
        let hops = match &app.screen {
            Screen::Browse(browse) => browse
                .ssh
                .keys
                .iter()
                .position(|row| row.tag == "laptop")
                .unwrap(),
            _ => panic!("key list"),
        };
        for _ in 0..hops {
            app.react(press_key('j'));
        }
        app.react(press_key('d'));
        type_text(&mut app, "laptop");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { body, .. } => assert!(body.contains("prod"), "{body}"),
                _ => panic!("a key used by a host should not delete"),
            },
            _ => panic!("a key used by a host should not delete"),
        }
        app.react(press_key('x'));

        choose_menu(&mut app, BrowseView::Hosts);
        app.react(press_key('d'));
        type_text(&mut app, "prod");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => assert!(browse.ssh.hosts.is_empty()),
            _ => panic!("host delete should clear the list"),
        }

        choose_menu(&mut app, BrowseView::Passwords);
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("No passwords."), "{view}");
        assert!(view.contains("c copy"), "{view}");
        assert!(view.contains("g generate"), "{view}");
        app.react(press_key('g'));
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        assert!(view.contains("Generate password"), "{view}");
        assert!(view.contains("length"), "{view}");
        assert!(view.contains("symbols"), "{view}");
        type_text(&mut app, "site");
        down(&mut app);
        type_text(&mut app, "12");
        down(&mut app);
        type_text(&mut app, "n");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { body, .. } => {
                    assert!(body.contains("copied"), "{body}");
                    assert!(body.contains("site"), "{body}");
                }
                _ => panic!("generate should copy the new password"),
            },
            _ => panic!("generate should stay on the password list"),
        }
        let generated = crate::ssh::take_copied().expect("generated password");
        assert_eq!(generated.chars().count(), 12);
        assert!(generated.chars().all(|ch| ch.is_ascii_alphanumeric()));
        app.react(press_key('x'));
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        assert!(view.contains("site"), "{view}");
        assert!(!view.contains(&generated), "{view}");
        app.react(press_key('c'));
        assert_eq!(
            crate::ssh::take_copied().as_deref(),
            Some(generated.as_str())
        );
        app.react(press_key('x'));

        app.react(press_key('n'));
        type_text(&mut app, "laptop");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::PageForm(form) => {
                    assert!(form.error.contains("already exists"), "{}", form.error)
                }
                _ => panic!("a key tag should block a password tag"),
            },
            _ => panic!("a key tag should block a password tag"),
        }
        app.react(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

        app.react(press_key('n'));
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        assert!(view.contains("New password"), "{view}");
        assert!(view.contains("confirm"), "{view}");
        type_text(&mut app, "other");
        down(&mut app);
        type_text(&mut app, "hunter2hunter2");
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        assert!(!view.contains("hunter2"), "{view}");
        assert!(view.contains('●'), "{view}");
        down(&mut app);
        type_text(&mut app, "hunter2hunter2NO");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::PageForm(form) => {
                    assert!(form.error.contains("did not match"), "{}", form.error);
                    assert!(form.fields[1].value.is_empty());
                    assert!(form.fields[2].value.is_empty());
                }
                _ => panic!("a mismatched password should be retyped"),
            },
            _ => panic!("a mismatched password should be retyped"),
        }
        type_text(&mut app, "hunter2hunter2");
        down(&mut app);
        type_text(&mut app, "hunter2hunter2");
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => {
                assert!(matches!(browse.prompt, Prompt::None));
                assert_eq!(browse.ssh.passwords.len(), 2);
            }
            _ => panic!("added password should return to the list"),
        }
        assert!(crate::ssh::take_copied().is_none());
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        assert!(view.contains("other"), "{view}");
        assert!(!view.contains("hunter2"), "{view}");
        app.react(press_key('c'));
        assert_eq!(crate::ssh::take_copied().as_deref(), Some("hunter2hunter2"));
        app.react(press_key('x'));

        choose_menu(&mut app, BrowseView::Files);
        match &app.screen {
            Screen::Browse(browse) => {
                assert_eq!(browse.view, BrowseView::Files);
                assert!(browse
                    .entries
                    .iter()
                    .any(|entry| entry.name == "ssh" && entry.kind == hdnfs::Kind::Dir));
            }
            _ => panic!("menu should return to files"),
        }
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let view = terminal.backend().to_string();
        assert!(view.contains("ssh"), "{view}");

        app.react(press_key('/'));
        app.react(press_key('m'));
        match &app.screen {
            Screen::Browse(browse) => {
                assert_eq!(browse.view, BrowseView::Files);
                let query = browse.find.as_ref().map(|find| find.query.as_str());
                assert_eq!(query, Some("m"));
            }
            _ => panic!("find should keep m"),
        }
    }

    fn choose_menu(app: &mut App, target: BrowseView) {
        app.react(press_key('m'));
        let cursor = match &app.screen {
            Screen::Browse(browse) => {
                assert!(browse.menu.open);
                browse.menu.cursor
            }
            _ => panic!("menu should be open"),
        };
        let target_index = MENU_ITEMS
            .iter()
            .position(|item| *item == target)
            .expect("menu item");
        let steps = (target_index + MENU_ITEMS.len() - cursor) % MENU_ITEMS.len();
        for _ in 0..steps {
            app.react(press_key('j'));
        }
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => {
                assert!(!browse.menu.open);
                assert_eq!(browse.view, target);
            }
            _ => panic!("menu choice should stay in the browser"),
        }
    }

    fn menu_item_highlighted(buffer: &ratatui::buffer::Buffer, name: &str) -> bool {
        (0..buffer.area.height).any(|y| {
            let text = row_text(buffer, y);
            if !text.contains(name) || text.contains("HDNFS") {
                return false;
            }
            (0..buffer.area.width).any(|x| buffer[(x, y)].bg == SAGE)
        })
    }

    fn type_text(app: &mut App, text: &str) {
        for ch in text.chars() {
            app.react(press_key(ch));
        }
    }

    fn down(app: &mut App) {
        app.react(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
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
    fn health_screen_paints_the_scan_and_the_report() {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        let running = HealthView {
            stage: "/docs/note".into(),
            done: 3,
            total: 10,
            report: None,
            error: None,
        };
        terminal
            .draw(|frame| draw_health(frame, &running, true))
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("/docs/note"), "{view}");
        assert!(view.contains("3 / 10 blocks"), "{view}");
        assert!(view.contains("cancel"), "{view}");
        assert_eq!(
            text_bg(terminal.backend().buffer(), "/docs/note"),
            INK,
            "progress dialog background\n{view}"
        );

        let finished = HealthView {
            stage: String::new(),
            done: 10,
            total: 10,
            report: Some(HealthReport {
                checked_blocks: 20,
                repaired_blocks: 1,
                unrepairable: 0,
            }),
            error: None,
        };
        terminal
            .draw(|frame| draw_health(frame, &finished, false))
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("checked"), "{view}");
        assert!(view.contains("repaired"), "{view}");
        assert!(view.contains("unrepairable"), "{view}");
        assert!(view.contains("close"), "{view}");
        assert!(!view.contains("quit"), "{view}");
        assert_eq!(
            text_bg(terminal.backend().buffer(), "checked"),
            INK,
            "report background\n{view}"
        );
    }

    #[test]
    fn backup_screen_paints_byte_progress() {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| draw_backup_progress(frame, "/tmp/vault.bak", 4096, 8192))
            .unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("Backup"), "{view}");
        assert!(view.contains("/tmp/vault.bak"), "{view}");
        assert!(view.contains("4.0 K / 8.0 K"), "{view}");
        assert!(view.contains("cancel"), "{view}");
        assert!(!view.contains("MiB"), "{view}");
    }

    #[test]
    fn w_backs_up_the_volume_image_to_the_typed_path() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = Tmp::new();
        let path = tmp.path.join("vol.img");
        let dest = tmp.path.join("vol.bak");
        hdnfs::init_volume(hdnfs::InitOptions {
            path: &path,
            password: "correct horse battery",
            size: Some(17 * 1024 * 1024),
            force: false,
            kdf: hdnfs::KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            progress: None,
        })
        .unwrap();
        let volume = Volume::open(&path, "correct horse battery", LockMode::Exclusive).unwrap();
        let mut app = App {
            screen: Screen::Browse(Browse::open(path.clone(), volume).unwrap()),
            ignore_repeat: None,
            job: None,
            alert: None,
            pending_ssh: None,
            dial: None,
            last_frame: RefCell::new(None),
        };

        app.react(repeat_key('w'));
        assert!(matches!(
            &app.screen,
            Screen::Browse(browse) if matches!(browse.prompt, Prompt::None)
        ));

        app.react(press_key('w'));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Line { title, value } => {
                    assert_eq!(*title, "backup path");
                    assert!(value.is_empty());
                }
                _ => panic!("w should ask for a path"),
            },
            _ => panic!("w should stay in the browser"),
        }
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("backup path"), "{view}");
        assert!(view.contains("confirm"), "{view}");
        assert!(view.contains("cancel"), "{view}");

        app.react(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(
            &app.screen,
            Screen::Browse(browse) if matches!(browse.prompt, Prompt::None)
        ));
        assert!(!dest.exists());

        app.react(press_key('w'));
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { title, body } => {
                    assert_eq!(title, "Backup");
                    assert_eq!(body, "empty input");
                }
                _ => panic!("an empty path should be rejected"),
            },
            _ => panic!("an empty path should stay in the browser"),
        }
        app.react(press_key('x'));

        app.react(press_key('w'));
        type_text(&mut app, &dest.display().to_string());
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { title, body } => {
                    assert_eq!(title, "Backup");
                    assert!(body.starts_with("wrote "), "{body}");
                    assert!(body.contains(&dest.display().to_string()), "{body}");
                }
                _ => panic!("a finished backup should show a note"),
            },
            _ => panic!("a finished backup should stay in the browser"),
        }
        let backup = std::fs::read(&dest).unwrap();
        assert!(backup.starts_with(b"HDNFS2\0\0"));
        let volume_len = std::fs::metadata(&path).unwrap().len();
        assert!((backup.len() as u64) < volume_len);
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn d_deletes_the_cursor_entry_after_confirmation() {
        let tmp = Tmp::new();
        let path = tmp.path.join("vol.img");
        hdnfs::init_volume(hdnfs::InitOptions {
            path: &path,
            password: "correct horse battery",
            size: Some(64 * 1024 * 1024),
            force: false,
            kdf: hdnfs::KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            progress: None,
        })
        .unwrap();
        let mut volume = Volume::open(&path, "correct horse battery", LockMode::Exclusive).unwrap();
        volume.write_bytes("/note.txt", b"hello").unwrap();
        volume.mkdir("/empty").unwrap();
        volume.mkdir("/full").unwrap();
        volume.write_bytes("/full/inner.txt", b"x").unwrap();
        let mut app = App {
            screen: Screen::Browse(Browse::open(path, volume).unwrap()),
            ignore_repeat: None,
            job: None,
            alert: None,
            pending_ssh: None,
            dial: None,
            last_frame: RefCell::new(None),
        };
        let names = |app: &App| {
            let Screen::Browse(browse) = &app.screen else {
                panic!("browser");
            };
            browse
                .entries
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>()
        };
        let select = |app: &mut App, name: &str| {
            let index = {
                let Screen::Browse(browse) = &app.screen else {
                    panic!("browser");
                };
                browse
                    .entries
                    .iter()
                    .position(|entry| entry.name == name)
                    .unwrap_or_else(|| panic!("{name} missing in {:?}", names_of(browse)))
            };
            let Screen::Browse(browse) = &mut app.screen else {
                panic!("browser");
            };
            browse.selected = index;
        };

        select(&mut app, "note.txt");
        assert!(matches!(app.react(press_key('d')), Apply::Stay));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Delete { path, kind } => {
                    assert_eq!(path, "/note.txt");
                    assert_eq!(*kind, Kind::File);
                }
                _ => panic!("d should ask before deleting"),
            },
            _ => panic!("d should stay in the browser"),
        }
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert_painted(terminal.backend());
        let view = terminal.backend().to_string();
        assert!(view.contains("Delete file"), "{view}");
        assert!(view.contains("/note.txt"), "{view}");
        assert!(view.contains("enter"), "{view}");
        assert!(view.contains("confirm"), "{view}");
        assert!(view.contains("esc"), "{view}");
        assert!(view.contains("cancel"), "{view}");
        assert!(!view.contains("y delete"), "{view}");
        assert_eq!(
            text_bg(terminal.backend().buffer(), "/note.txt"),
            INK,
            "delete dialog background\n{view}"
        );
        app.react(press_key('y'));
        assert!(matches!(
            &app.screen,
            Screen::Browse(browse) if matches!(browse.prompt, Prompt::Delete { .. })
        ));
        app.react(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(
            &app.screen,
            Screen::Browse(browse) if matches!(browse.prompt, Prompt::None)
        ));
        assert!(names(&app).contains(&"note.txt".to_string()));

        select(&mut app, "note.txt");
        app.react(press_key('d'));
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            &app.screen,
            Screen::Browse(browse) if matches!(browse.prompt, Prompt::None)
        ));
        assert!(!names(&app).contains(&"note.txt".to_string()));

        select(&mut app, "empty");
        app.react(press_key('d'));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Delete { path, kind } => {
                    assert_eq!(path, "/empty");
                    assert_eq!(*kind, Kind::Dir);
                }
                _ => panic!("d should ask before deleting a directory"),
            },
            _ => panic!("d should stay in the browser"),
        }
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!names(&app).contains(&"empty".to_string()));

        select(&mut app, "full");
        app.react(press_key('d'));
        app.react(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match &app.screen {
            Screen::Browse(browse) => match &browse.prompt {
                Prompt::Note { body, .. } => assert!(body.contains("not empty"), "{body}"),
                _ => panic!("a directory with children should stay"),
            },
            _ => panic!("a directory with children should stay in the browser"),
        }
        assert!(names(&app).contains(&"full".to_string()));
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

    fn names_of(browse: &Browse) -> Vec<&str> {
        browse
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect()
    }

    fn text_bg(buffer: &ratatui::buffer::Buffer, needle: &str) -> Color {
        for y in 0..buffer.area.height {
            let mut line = String::new();
            let mut colors = Vec::new();
            for x in 0..buffer.area.width {
                let cell = &buffer[(x, y)];
                line.push_str(cell.symbol());
                colors.push(cell.bg);
            }
            if let Some(at) = line.find(needle) {
                return colors[at];
            }
        }
        panic!("{needle} is not on screen");
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
