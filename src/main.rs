/*!
 * # Sbsevery
 *
 * Secure boot sign every(thing)
 *
 * Recursively sign files for secureboot (helpful when dualbooting Windows with custom SB keys)
 *
 * ## Usage
 *
 * quietly sign all files
 * ```
 * sbsevery /efi -k /etc/efi-keys/DB.key -c /etc/efi-keys/DB.crt
 * ```
 *
 * verbosely sign all files
 * ```
 * sbsevery /efi -k /etc/efi-keys/DB.key -c /etc/efi-keys/DB.crt -d
 * ```
 */

#![feature(thread_is_running)]

use std::{
    path::{Path, PathBuf},
    sync::{mpsc::{channel, Sender}, Arc},
    thread::{JoinHandle, spawn}, process::ExitStatus,
};

use jargon_args::Jargon;

macro_rules! dprintln {
    ($b:expr, $($arg:tt)*) => ({
        if $b {
            eprintln!($($arg)*);
        }
    })
}

fn main() {
    if let Err(e) = main_prog() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn main_prog() -> Result<(), Box<dyn std::error::Error>> {
    let (sx, rx) = channel();
    let (esx, erx) = channel();

    let mut jargon = Jargon::from_env();

    let verbose = jargon.contains(["-v", "--verbose"]);
    let key_path: PathBuf = jargon.result_arg(["-k", "--key"])?;
    let cert_path: PathBuf = jargon.result_arg(["-c", "--cert"])?;

    let mut directories: Vec<PathBuf> = jargon
        .finish()
        .iter()
        .map(|p| PathBuf::from(p))
        .collect();
    
    let searcher = spawn(move || searcher(sx, esx, directories));

    let mut threads = Vec::new();

    while searcher.is_running() {
        if let Ok(path) = rx.recv() {
            let key_path = key_path.clone();
            let cert_path = cert_path.clone();
            let t = spawn(move || sign_file(path, key_path, cert_path));
            threads.push(t);
        }
    }

    let thread_count = threads.len();
    let mut failures = 0;

    for t in threads {
        if let Ok(res) = t.join() {
            match res {
                Ok(status) => if !status.success() { failures += 1 },
                Err(_) => failures += 1,
             }
        }
    }

    eprintln!("ran {} threads with {} failures", thread_count, failures);

    Ok(())
}

fn sign_file(
    file: PathBuf,
    key: PathBuf,
    cert: PathBuf,
) -> Result<ExitStatus, std::io::Error> {
    let debug = true;
    dprintln!(debug, "signing: {}", file.display());

    let mut child = std::process::Command::new("sbsign")
        .arg("--key")
        .arg(key.as_os_str())
        .arg("--cert")
        .arg(cert.as_os_str())
        .arg("--output")
        .arg(&file)
        .arg(&file)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    child.wait()
}

fn searcher(sx: Sender<PathBuf>, esx: Sender<bool>, directories: Vec<PathBuf>) {
    for dir in directories {
        match dir.is_dir() {
            true => push_dir(&sx, dir),
            false => push_file(&sx, dir),
        }
    }
}

fn push_dir(sx: &Sender<PathBuf>, dir: PathBuf) {
    if let Some(dir) = dir.read_dir().ok() {
        for entry in dir {
            if let Ok(entry) = entry {
                match entry.path().is_dir() {
                    true => push_dir(sx, entry.path()),
                    false => push_file(sx, entry.path()),
                }
            }
        }
    }
}

fn push_file(sx: &Sender<PathBuf>, file: PathBuf) {
    eprintln!("pushing: {}", file.display());
    sx.send(file);
}
