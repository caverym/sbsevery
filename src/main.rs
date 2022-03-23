#![warn(clippy::all, clippy::pedantic)]
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

use std::{
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::mpsc::{channel, Receiver, Sender},
    thread::{spawn, JoinHandle},
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
    let mut jargon = Jargon::from_env();
    let verbose = jargon.contains(["-v", "--verbose"]);
    let key_path: PathBuf = jargon.result_arg(["-k", "--key"])?;
    let cert_path: PathBuf = jargon.result_arg(["-c", "--cert"])?;
    let directories: Vec<PathBuf> = jargon.finish().iter().map(PathBuf::from).collect();
    let (sx, rx) = channel();

    spawn(move || searcher(&sx, directories, verbose));

    let mut threads = Vec::new();
    threader(&rx, &key_path, &cert_path, &mut threads, verbose);

    let thread_count = threads.len();
    let mut failures = 0;
    wait(threads, &mut failures);

    eprintln!("ran {} threads with {} failures", thread_count, failures);

    Ok(())
}

fn wait(
    threads: Vec<std::thread::JoinHandle<Result<ExitStatus, std::io::Error>>>,
    failures: &mut i32,
) {
    for t in threads {
        if let Ok(res) = t.join() {
            match res {
                Ok(status) => {
                    if !status.success() {
                        *failures += 1;
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        } else {
            eprintln!("Thread join failed");
        }
    }
}

fn threader(
    rx: &Receiver<PathBuf>,
    key_path: &Path,
    cert_path: &Path,
    threads: &mut Vec<JoinHandle<Result<ExitStatus, std::io::Error>>>,
    verbose: bool,
) {
    while let Ok(file) = rx.recv() {
        let key_path = key_path.to_path_buf();
        let cert_path = cert_path.to_path_buf();
        let t = spawn(move || sign_file(&file, &key_path, &cert_path, verbose));
        threads.push(t);
    }
}

fn sign_file(
    file: &Path,
    key: &Path,
    cert: &Path,
    verbose: bool,
) -> Result<ExitStatus, std::io::Error> {
    dprintln!(verbose, "signing:\t{}", file.display());

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

fn searcher(sx: &Sender<PathBuf>, directories: Vec<PathBuf>, verbose: bool) {
    for dir in directories {
        let err = if dir.is_dir() {
            push_dir(sx, &dir, verbose)
        } else {
            push_file(sx, &dir, verbose)
        };

        if let Err(e) = err {
            dprintln!(verbose, "error:\t{}", e);
        }
    }
}

fn push_dir(
    sx: &Sender<PathBuf>,
    dir: &Path,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    dprintln!(verbose, "expanding:\t{}", dir.display());
    if let Ok(dir) = dir.read_dir() {
        for entry in dir.flatten() {
            let entry = entry.path();

            if entry.is_dir() {
                push_dir(sx, &entry, verbose)?;
            } else {
                push_file(sx, &entry, verbose)?;
            }
        }
    }

    Ok(())
}

fn push_file(
    sx: &Sender<PathBuf>,
    file: &Path,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    dprintln!(verbose, "pushing:\t{}", file.display());
    sx.send(file.to_path_buf())?;
    Ok(())
}
