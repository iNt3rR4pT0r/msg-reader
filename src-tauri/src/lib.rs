use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_dialog::DialogExt;

mod printing;

/// Largest email file the webview may request (bytes).
const MAX_EMAIL_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Largest attachment that is written to disk for an external viewer (bytes).
const MAX_EXTERNAL_FILE_SIZE: usize = 256 * 1024 * 1024;

/// File types that may be handed to the system's default application.
/// Everything the frontend opens externally today is a PDF. Anything that the
/// operating system would *execute* (.exe, .bat, .lnk, .js, ...) must never be
/// added here: the file content comes straight out of an email.
const EXTERNALLY_OPENABLE_EXTENSIONS: &[&str] = &["pdf"];

/// Store pending file paths for when app is launched via file association
pub struct PendingFiles(pub Mutex<Vec<PathBuf>>);

/// Canonical paths of the email files the *user* handed to the app (file
/// association, command line, drag & drop). The webview can only read these.
pub struct AllowedFiles(pub Mutex<HashSet<PathBuf>>);

/// Temporary directories created for externally opened attachments.
pub struct TempDirs(pub Mutex<Vec<PathBuf>>);

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// True if the path has an email file extension (.msg / .eml)
fn is_email_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .is_some_and(|e| e == "msg" || e == "eml")
}

/// Remember a user-selected email file so the webview is allowed to read it.
fn allow_file(app: &AppHandle, path: &Path) {
    if !is_email_path(path) {
        return;
    }
    // Resolve symlinks first: the check must apply to the real target.
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return;
    };
    if !is_email_path(&canonical) {
        return;
    }
    if let Ok(mut allowed) = app.state::<AllowedFiles>().0.lock() {
        allowed.insert(canonical);
    }
}

/// Reduce an untrusted file name to a harmless base name.
///
/// Path components are dropped and every character outside a conservative
/// allow list is replaced, so the result can neither leave the target
/// directory nor carry shell metacharacters.
fn sanitize_file_name(file_name: &str) -> String {
    let base = file_name
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or_default();

    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_' | '(' | ')' | '[' | ']' | ',' | '+') {
                c
            } else {
                '_'
            }
        })
        .take(150)
        .collect();

    let cleaned = cleaned.trim_matches(|c| c == '.' || c == ' ').to_string();

    let stem = cleaned.split('.').next().unwrap_or_default().to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.ends_with(|c: char| c.is_ascii_digit()));

    if cleaned.is_empty() {
        "attachment".to_string()
    } else if reserved {
        format!("_{}", cleaned)
    } else {
        cleaned
    }
}

/// Create a fresh, private directory below the system temp directory.
fn create_private_temp_dir() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "msgreader-{}-{:x}-{}",
        std::process::id(),
        nanos,
        counter
    ));

    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    // Not recursive: fails if the directory already exists, so a prepared
    // directory or symlink at this location is never reused.
    builder
        .create(&dir)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;

    Ok(dir)
}

/// Read an email file from the filesystem and return its bytes.
///
/// Only .msg/.eml files that the user opened with the app are readable.
/// The webview renders untrusted email content, so it must not be able to
/// read arbitrary files.
#[tauri::command]
fn read_file_as_bytes(
    path: String,
    allowed: tauri::State<'_, AllowedFiles>,
) -> Result<Vec<u8>, String> {
    let canonical =
        std::fs::canonicalize(&path).map_err(|_| "File could not be opened".to_string())?;

    if !is_email_path(&canonical) {
        return Err("Only .msg and .eml files can be opened".to_string());
    }

    let is_allowed = allowed
        .0
        .lock()
        .map_err(|_| "Internal error".to_string())?
        .contains(&canonical);
    if !is_allowed {
        return Err("This file was not opened by the user".to_string());
    }

    let metadata =
        std::fs::metadata(&canonical).map_err(|_| "File could not be opened".to_string())?;
    if !metadata.is_file() {
        return Err("Not a regular file".to_string());
    }
    if metadata.len() > MAX_EMAIL_FILE_SIZE {
        return Err("File is too large".to_string());
    }

    std::fs::read(&canonical).map_err(|e| format!("Failed to read file: {}", e))
}

/// Save a base64-encoded attachment to a private temp directory and open it
/// with the system viewer.
#[tauri::command]
fn open_file_with_system(
    base64_content: String,
    file_name: String,
    temp_dirs: tauri::State<'_, TempDirs>,
) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let safe_name = sanitize_file_name(&file_name);
    let extension = Path::new(&safe_name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    if !EXTERNALLY_OPENABLE_EXTENSIONS.contains(&extension.as_str()) {
        return Err("This file type cannot be opened externally".to_string());
    }

    if base64_content.len() / 4 * 3 > MAX_EXTERNAL_FILE_SIZE {
        return Err("File is too large".to_string());
    }

    // Decode base64 content
    let bytes = STANDARD
        .decode(&base64_content)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    // The content has to be what the extension claims (PDF header within the
    // first 1024 bytes, as PDF readers require).
    let head = &bytes[..bytes.len().min(1024)];
    if !head.windows(5).any(|window| window == b"%PDF-") {
        return Err("File is not a valid PDF".to_string());
    }

    let temp_dir = create_private_temp_dir()?;
    if let Ok(mut dirs) = temp_dirs.0.lock() {
        dirs.push(temp_dir.clone());
    }
    let temp_path = temp_dir.join(&safe_name);

    // create_new: never follow or overwrite an existing file
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write temp file: {}", e))?;
    drop(file);

    // Hand the path to the OS directly (ShellExecute / open / xdg-open).
    // No shell is involved, so nothing in the path is interpreted as a command.
    tauri_plugin_opener::open_path(&temp_path, None::<&str>)
        .map_err(|e| format!("Failed to open file: {}", e))?;

    Ok(())
}

/// Save a file with a "Save As" dialog
#[tauri::command]
async fn save_file_with_dialog(
    app: AppHandle,
    base64_content: String,
    file_name: String,
) -> Result<bool, String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tauri_plugin_dialog::FilePath;

    // The suggested name comes from the email: keep the base name only.
    let file_name = sanitize_file_name(&file_name);

    // Extract file extension for filter
    let extension = std::path::Path::new(&file_name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();

    // Build the save dialog
    let mut dialog = app.dialog().file().set_file_name(&file_name);
    if !extension.is_empty() {
        dialog = dialog.add_filter("File", &[&extension]);
    }
    let file_path = dialog.blocking_save_file();

    match file_path {
        Some(FilePath::Path(path)) => {
            // Decode base64 content
            let bytes = STANDARD
                .decode(&base64_content)
                .map_err(|e| format!("Failed to decode base64: {}", e))?;

            // Write to the selected file
            let mut file = std::fs::File::create(&path)
                .map_err(|e| format!("Failed to create file: {}", e))?;
            file.write_all(&bytes)
                .map_err(|e| format!("Failed to write file: {}", e))?;

            Ok(true)
        }
        _ => Ok(false), // User cancelled
    }
}

/// Get files that were passed to the app on startup
#[tauri::command]
fn get_pending_files(state: tauri::State<'_, PendingFiles>) -> Vec<String> {
    let mut pending = state.0.lock().unwrap();
    let files: Vec<String> = pending.drain(..).map(|p| p.to_string_lossy().to_string()).collect();
    files
}

/// Handle a file being opened - emit event to frontend
fn handle_file_open(app: &AppHandle, path: PathBuf) {
    // Validate file extension
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());

    match ext.as_deref() {
        Some("msg") | Some("eml") => {
            allow_file(app, &path);
            // Emit event to frontend
            if let Err(e) = app.emit("file-open", path.to_string_lossy().to_string()) {
                eprintln!("Failed to emit file-open event: {}", e);
            }
        }
        _ => {
            eprintln!("Unsupported file type: {:?}", path);
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // Handle file opened when app is already running (Windows/Linux)
            if args.len() > 1 {
                let path = PathBuf::from(&args[1]);
                handle_file_open(app, path);
            }
            // Focus the main window
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }))
        .manage(PendingFiles(Mutex::new(Vec::new())))
        .manage(AllowedFiles(Mutex::new(HashSet::new())))
        .manage(TempDirs(Mutex::new(Vec::new())))
        // Files dropped onto the window are user-selected as well
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event {
                for path in paths {
                    allow_file(window.app_handle(), path);
                }
            }
        })
        .on_webview_event(|webview, event| {
            if let tauri::WebviewEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event {
                for path in paths {
                    allow_file(webview.app_handle(), path);
                }
            }
        })
        .setup(|app| {
            // Check for files passed as command-line arguments on startup (Windows/Linux)
            let args: Vec<String> = std::env::args().collect();
            for arg in args.iter().skip(1) {
                let path = PathBuf::from(arg);
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_lowercase());

                if matches!(ext.as_deref(), Some("msg") | Some("eml")) {
                    allow_file(app.handle(), &path);
                    // Store for later retrieval by frontend
                    app.state::<PendingFiles>()
                        .0
                        .lock()
                        .unwrap()
                        .push(path);
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![read_file_as_bytes, get_pending_files, open_file_with_system, save_file_with_dialog, printing::print_message]);

    builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // Handle macOS file open events (double-click on file)
            // This event only exists on macOS
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Opened { urls } = &event {
                for url in urls {
                    // Convert file:// URL to path
                    if let Ok(path) = url.to_file_path() {
                        // Check if app is ready (has windows)
                        if app.get_webview_window("main").is_some() {
                            // App is running, emit event
                            handle_file_open(app, path);
                        } else {
                            // App is starting up, store for later
                            let ext = path
                                .extension()
                                .and_then(|e| e.to_str())
                                .map(|e| e.to_lowercase());

                            if matches!(ext.as_deref(), Some("msg") | Some("eml")) {
                                allow_file(app, &path);
                                app.state::<PendingFiles>()
                                    .0
                                    .lock()
                                    .unwrap()
                                    .push(path);
                            }
                        }
                    }
                }
            }

            // Remove the temp copies of externally opened attachments on exit.
            // Files still held open by a viewer are left behind (best effort).
            if let tauri::RunEvent::Exit = &event {
                if let Ok(mut dirs) = app.state::<TempDirs>().0.lock() {
                    for dir in dirs.drain(..) {
                        let _ = std::fs::remove_dir_all(dir);
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_lose_path_components() {
        assert_eq!(sanitize_file_name("../../etc/passwd.pdf"), "passwd.pdf");
        assert_eq!(sanitize_file_name("C:\\Windows\\System32\\evil.pdf"), "evil.pdf");
        assert_eq!(sanitize_file_name("/abs/olute.pdf"), "olute.pdf");
        assert_eq!(sanitize_file_name(".."), "attachment");
        assert_eq!(sanitize_file_name(""), "attachment");
    }

    #[test]
    fn file_names_lose_shell_metacharacters() {
        let name = sanitize_file_name("a&calc|b^c%PATH%;d\"e'f`g$h<i>j.pdf");
        assert_eq!(name, "a_calc_b_c_PATH__d_e_f_g_h_i_j.pdf");
        assert!(!name.contains(['&', '|', '^', '%', ';', '"', '\'', '`', '$', '<', '>']));
    }

    #[test]
    fn file_names_keep_ordinary_names() {
        assert_eq!(sanitize_file_name("Rechnung 2024-05 (final).pdf"), "Rechnung 2024-05 (final).pdf");
        assert_eq!(sanitize_file_name("Übersicht_größe.pdf"), "Übersicht_größe.pdf");
    }

    #[test]
    fn reserved_device_names_are_defused() {
        assert_eq!(sanitize_file_name("CON.pdf"), "_CON.pdf");
        assert_eq!(sanitize_file_name("com1.pdf"), "_com1.pdf");
        assert_eq!(sanitize_file_name("nul"), "_nul");
        assert_eq!(sanitize_file_name("console.pdf"), "console.pdf");
    }

    #[test]
    fn only_email_extensions_are_readable() {
        assert!(is_email_path(Path::new("/tmp/a.msg")));
        assert!(is_email_path(Path::new("/tmp/a.EML")));
        assert!(!is_email_path(Path::new("/home/user/.ssh/id_rsa")));
        assert!(!is_email_path(Path::new("/tmp/a.msg.exe")));
        assert!(!is_email_path(Path::new("/tmp/msg")));
    }

    #[test]
    fn temp_dirs_are_unique() {
        let first = create_private_temp_dir().unwrap();
        let second = create_private_temp_dir().unwrap();
        assert_ne!(first, second);
        assert!(first.is_dir() && second.is_dir());
        let _ = std::fs::remove_dir_all(first);
        let _ = std::fs::remove_dir_all(second);
    }
}
