# NtSentry AIO Process Viewer

A Windows utility that looks for signs of userland tampering and shows them, together with a full system inventory, in an egui dashboard for a person to review. Scans are read-only: they never write to process memory, change page protection, or restore ("unhook") bytes. The only changes the program makes are process actions that you confirm.

## The dashboard

- **Menu bar:** File (exports, data folder, findings log), Edit (copy, open file location), View (refresh, pause, filters, zoom, theme), Scan, Baseline, Settings, Help.
- **Findings pane** (always visible): everything the scans found, most severe first. **NEW** marks findings that were not in the previous scan of the same kind; the previous scan is read from the log, so this works across restarts.
- **Inventory tabs:** Processes (live CPU, memory, threads, session, user, start time and, optionally, command line), Services, Drivers, Startup, Connections and Quarantine. Every entry is shown. Click a column header to sort; CPU %, Memory, Threads and Size start with the largest. Processes, services, drivers and startup entries carry a **Flag** column with their worst finding.
- **Columns:** right-click a column header > Columns to show or hide columns. Copies and exports include only the shown columns; the full JSON report always has everything.
- **Selecting rows:** click, Ctrl+click, Shift+click, arrow keys and Shift+arrow keys, Home/End, PageUp/PageDown, Ctrl+A for all. Ctrl+C copies the selected rows as tab-separated text; right-click acts on all selected rows.
- **Process tree:** View > Process tree (or the Tree box) shows parent/child relationships. A parent that started after its child is a reused PID, so that child is shown as a root. Sorting orders each parent's children and the top-level processes.
- **Details pane:** click any row. Findings come with a plain-English **What this means / What you can do** section. Other rows list their related findings; a process also shows its user, start time, command line, file version information, loaded modules and network endpoints.
- **Files:** Open file location, File properties (the standard Windows dialog), and Look up on VirusTotal, which hashes the file locally and opens your browser at its VirusTotal page. Only the SHA-256 leaves the PC, and only when you click.
- **Notification area:** a tray icon with Show dashboard / Scan now / Exit. Minimizing hides the window to the tray (setting). The icon turns red and its tooltip shows the alert while one is active.
- **Find** (Ctrl+F) filters the findings and the current tab by any text.
- **Shortcuts:** F5 refresh, Ctrl+S export the current view, Ctrl+A select all, Ctrl+C copy, Esc clear the selection.
- **Layout is remembered:** window size and position, pane sizes, column widths, hidden columns, sort order and the last tab.

Command lines can contain sensitive arguments such as tokens. They are only shown on screen, and only exported when the Command line column is shown.

### Process actions

Right-click a process, or use the details pane or the Edit menu. With several processes selected, an action applies to all of them after one confirmation:

| Action | What happens |
|---|---|
| **End process…** | Asks first, then ends the process and waits up to 5 s for it to exit. |
| **End process tree…** | Asks first, listing every process, then ends the process and everything it started, children first. A "parent" that started after its child is a reused PID and is not followed. |
| **Suspend / Resume** | Suspends every thread. Only threads the dashboard suspended are ever resumed, and everything still suspended is resumed when the dashboard exits. |
| **End and quarantine file…** | Asks first, ends the process, copies its file into `quarantine\<id>\` (masked so it cannot run, with a manifest and SHA-256), verifies the copy, then deletes the original. If the original cannot be deleted, the copy is kept and you are told. |
| **Restore** (Quarantine tab) | Asks first, writes the file back only if nothing exists at the original path, and checks the hash. The entry is kept as `<id>.restored`. |

Before any action the PID and its start time are re-checked, so a PID that now belongs to another program is never touched. Idle, System, Windows critical processes and the dashboard itself are refused. Files under the Windows folder cannot be quarantined. Every action, successful or not, is written to `findings.jsonl` (kind `action`). The masking is obfuscation, not encryption.

### Settings

Settings save automatically to `settings.json` in the data folder.

| Setting | Default |
|---|---|
| Run at Windows sign-in, minimized (`HKCU\…\CurrentVersion\Run`, current user only) | Off |
| Scan when the dashboard opens | On |
| Scan and log every N minutes | On, 60 min |
| Refresh live data every N seconds; inventories every 15 s | On, 2 s |
| Alert (flash the taskbar, banner, red tray icon) on new findings at or above a severity | On, Medium |
| Write new findings at or above a severity to the Windows Application event log | Off, High |
| Minimize to the notification area | On |
| Include the three deep checks below in Scan all and scheduled scans | On |

Exports use a Save As dialog. The options are the current view as CSV, findings as CSV or JSON, and a full JSON report of findings plus all inventories. CSV cells that start with `=`, `+`, `-` or `@` are prefixed with `'`, so spreadsheet programs don't evaluate them as formulas.

### Deep checks

| Check | What it reports |
|---|---|
| **ntdll across processes** | ntdll's code in every readable process, compared with the dashboard's own copy. Shared image pages only differ after a write, so differences are modifications. Each hook's jump target is decoded and attributed to the module (or anonymous memory) that owns it. The program's own signed code, typical of browser and Electron sandboxes, is Info; other signed modules in Program Files or Windows are Low; memory not backed by a file is Medium; unsigned, untrusted, or temp/user-folder modules are High. One finding per process and owner. |
| **Loaded modules** | Signed processes that loaded an unsigned, untrusted or invalidly signed DLL from a temp or user-writable folder (side-loading or injection). Only DLLs in those folders are signature-checked, so the scan is fast. |
| **Persistence** | Services, drivers and startup entries: missing files (a running driver whose file is gone is High), temp or user-writable locations, signatures, URLs in commands, script hosts and startup scripts. Startup-folder shortcuts are resolved to their targets. Stopped drivers are checked for location only. |
| **Drivers** | Runs with the persistence audit. How Windows guards drivers: signature enforcement off (Critical), test signing (High), kernel debugging (Medium), Memory integrity off (Low), vulnerable-driver blocklist off (Medium). Every kernel module actually loaded is compared with the registered drivers: one loaded without a registration from outside Windows is Medium, from a user-writable folder or with a missing file or untrusted signature High. Driver files whose names match a short built-in list of drivers publicly documented as abused for kernel access are Medium when loaded and Low when only installed; a name match is a lead, not proof. A running driver from outside Windows and Program Files is Low. |
| **Process lineage** (part of the process scan) | Office starting a shell or script host; browsers starting script hosts; `svchost`, `lsass`, `lsaiso` or `services` with an unexpected parent. |

Signature results are cached across all scans. *Untrusted* (self-signed, expired or unknown root) is graded like unsigned. *Invalid* covers a changed file, a revoked or distrusted certificate, or another verification failure, and is High. A file that could not be read counts as "not checked", not as invalid.

### Event log

When enabled, new findings go to the Application log under source `NtSentry`, event ID 1000 + severity (Low 1001 … Critical 1004). Registering a message file needs administrator rights, so Event Viewer shows a "description cannot be found" preamble; the finding text follows it in full.

### Log rotation

`findings.jsonl` is renamed to `findings-<unix time>.jsonl` once it reaches 16 MB, and a new file is started. Old logs are kept.

## Modules

| File | Purpose |
|---|---|
| `src/integrity_monitor.rs` | Module A: ntdll.dll integrity against a baseline and the on-disk file; cross-process sweep with hook attribution |
| `src/process_inventory.rs` | Module B: process list with signature, location, and name checks |
| `src/system.rs` | Windows inventories (live process metrics, services, drivers, startup entries, connections, modules, file version info) and the guarded end/suspend/resume controls |
| `src/inventory.rs` | Inventory collection; command-line and shortcut resolution |
| `src/persistence_audit.rs` | Services, drivers and startup entries |
| `src/driver_audit.rs` | Code integrity state, loaded kernel modules and known-abusable drivers |
| `src/module_audit.rs` | Unsigned DLLs in signed processes |
| `src/eventlog.rs` | Opt-in Application event log output |
| `src/quarantine.rs` | Restorable quarantine |
| `src/tray.rs` | Notification-area icon and the window icon |
| `src/explain.rs` | Plain-English help for each kind of finding |
| `assets/` | Icon (`make_icons.py` regenerates it) and the Windows resource script |
| `build.rs` | Embeds the icon and version details into `ntsentry.exe` |
| `src/worker.rs` | Scan thread and live-refresh thread; results reach the UI over `std::sync::mpsc` |
| `src/app.rs` | The egui dashboard |
| `src/main.rs` | Entry point and headless CLI |
| `src/settings.rs`, `src/autostart.rs` | Preferences and the opt-in sign-in entry |
| `src/export.rs`, `src/dialogs.rs` | CSV/JSON exports and the Save As dialog |
| `src/pe.rs` | Bounds-checked PE reader (sections, relocations, exports, function overrides) |
| `src/signature.rs` | Authenticode check: embedded signature, then the Windows catalog |
| `src/storage.rs` | Baseline storage and the append-only findings log |

### Module A: ntdll integrity

1. Reads `%SystemRoot%\System32\ntdll.dll` read-only and records its SHA-256, size, and Authenticode result (offline policy: cached URLs, no live revocation check).
2. Copies every executable section of the ntdll mapped into this process with `ReadProcessMemory`, then reverses the loader's base relocations on the copy so bytes compare across boots.
3. **With a baseline**, it reports deviations from the baseline. Differences from disk that already existed at capture time (for example a security product's hooks) are summarised once at Info.
4. **Without a baseline**, it reports every difference from the on-disk file.
5. Each difference run is a finding with its RVA, the nearest export (`NtOpenProcess+0x3`), and expected vs observed bytes. A run touching an export's first 16 bytes is High ("possible inline hook"); other runs are Medium.
6. It also flags:
   - code pages that are currently writable;
   - unreadable pages;
   - an unexpected load path;
   - a signer change;
   - a baseline file whose hash no longer matches.

**Windows function overrides.** On current Windows 11 builds the OS retargets a few `jmp rel32` thunks in ntdll's `fothk` section at load time. These sites are declared in the signed file's dynamic relocation table. Rather than ignore them, the monitor parses that table and checks each site's in-memory target:
- Accepted: the declared original, a declared alternative, or an executable page appended to ntdll's own image allocation. These are reported at Info.
- Anything else is High ("thunk redirected outside ntdll").

**Scope limit:** only the ntdll mapping inside the dashboard's own process is inspected. A hook placed only in another process is not visible to this module.

### Module B: process inventory

`CreateToolhelp32Snapshot` enumerates processes. `QueryFullProcessImageNameW` resolves each image path through a `PROCESS_QUERY_LIMITED_INFORMATION` handle. Findings:

| Condition | Severity |
|---|---|
| System process name (svchost, lsass, csrss, ...) running outside where Windows keeps it | High |
| Signature present but does not verify | High |
| Unsigned image in Temp / Downloads / Recycle Bin | High |
| Unsigned image elsewhere in a user profile, Public, or ProgramData | Medium |
| Unsigned image under the Windows directory | Medium |
| Snapshot name differs from the image file name | Medium |
| Unsigned image elsewhere | Low |
| Signed image in Temp / Downloads | Low |

Run as administrator, NtSentry turns on the debug privilege (as Task Manager and Process Explorer do) so query-only handles open for service and protected processes; the status bar says whether it runs as administrator. A process that still refuses access (some anti-cheat protected ones) gets its path from a handle-free kernel query, so its file and signature are still checked; its user, CPU and memory stay blank. The memory-reading checks (ntdll sweep, module audit) skip lsass.exe: it holds sign-in secrets, and Windows credential-theft protection flags any tool that opens it for reading. Signature results are cached by path, size, and modification time.

## Baseline

Capture the baseline on a machine you trust is clean ("Capture baseline" in the toolbar, or `--capture-baseline`). Capture is refused when:
- the file's signature does not verify;
- the loaded ntdll build differs from the file (reboot first);
- the current state already has Medium-or-higher warnings.

The baseline lives in `%LOCALAPPDATA%\NtSentry\baseline\` (override with `NTSENTRY_DATA`). It is written into a staging folder and renamed into place, and it is never overwritten. To re-baseline after a Windows update, use "Archive baseline…"; it renames the old one to `baseline-archived-<unix time>` and deletes nothing.

The baseline is stored in a user-writable folder and protected only by recorded hashes. Malware running as the same user could rewrite both the snapshot and its hashes. For stronger assurance, keep a copy of `baseline.json` offline and compare its `file_sha256`.

## Logs

Each scan appends one JSON line (`{"unix", "scan", "findings"}`) to `findings.jsonl` in the data folder.

## Build, test, run

Requires the Rust MSVC toolchain, the Visual Studio C++ build tools and the Windows SDK. `build.ps1` loads the MSVC environment, because Git for Windows ships an unrelated `link.exe`, and puts `rc.exe` on the path so `build.rs` can embed the icon. Without `rc.exe` the build still works, just without an embedded icon.

```powershell
.\build.ps1 test      # unit tests + read-only live-system tests
.\build.ps1 clippy
.\build.ps1 release   # target\release\ntsentry.exe
```

Headless use (output files are never overwritten):

```powershell
ntsentry.exe --scan NEW-report.json
ntsentry.exe --capture-baseline NEW-capture.json
```

The live-system tests write baselines and quarantine entries only into fresh temporary folders and remove them afterwards. One test alters a *stored baseline file* to confirm tampering is detected. The control tests suspend, resume and end only a `cmd.exe` child that the test starts itself. No test writes to any process's memory.
