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
    sync::Arc,
    thread::{self, JoinHandle},
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
    if let Err(e) = prog_main() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn prog_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser: Jargon = Jargon::from_env();

    let mut key: PathBuf = parser.result_arg(["-k", "--key"])?;
    let mut cert: PathBuf = parser.result_arg(["-c", "--cert"])?;
    let debug = parser.contains(["-d", "--debug"]);

    key = key.canonicalize()?;
    cert = cert.canonicalize()?;

    let key: Arc<PathBuf> = Arc::new(key);
    let cert: Arc<PathBuf> = Arc::new(cert);

    let files = collect_files(parser_to_vec(parser), debug)?;

    sign_everything(files, key, cert, debug)
}

fn sign_everything(
    files: Vec<PathBuf>,
    key: Arc<PathBuf>,
    cert: Arc<PathBuf>,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut threads: Vec<JoinHandle<Result<(), std::io::Error>>> = Vec::new();

    let fcount = if debug { files.len() } else { 0 };

    for file in files {
        let key = key.clone();
        let cert = cert.clone();
        let debug = debug.clone();
        let handle = thread::spawn(move || sign_thread(file, key, cert, debug));
        threads.push(handle)
    }

    let tcount = if debug { threads.len() } else { 0 };

    let mut fails = 0;
    for thread in threads {
        if let Err(e) = thread.join() {
            println!("{:?}", e);
            fails += 1;
        }
    }

    dprintln!(debug,
        "Pushed files:\t{}\nThreads:\t{}\nfailures:\t{}",
        fcount, tcount, fails 
    );

    Ok(())
}

fn sign_thread(
    file: PathBuf,
    key: Arc<PathBuf>,
    cert: Arc<PathBuf>,
    debug: bool,
) -> Result<(), std::io::Error> {
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
    child.wait()?;
    Ok(())
}

fn parser_to_vec(parser: Jargon) -> Vec<PathBuf> {
    parser.finish().iter().map(|p| PathBuf::from(p)).collect()
}

fn collect_files(
    paths: Vec<PathBuf>,
    debug: bool,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut result = Vec::new();
    for path in paths {
        match path.is_file() {
            true => push_file(&mut result, &path, debug)?,
            false => push_dir(&mut result, &path, debug)?,
        }
    }

    Ok(result)
}

fn push_file(
    result: &mut Vec<PathBuf>,
    path: &Path,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = path.canonicalize()?;
    dprintln!(debug, "pushing: {}", path.display());
    result.push(path);
    Ok(())
}

fn push_dir(
    result: &mut Vec<PathBuf>,
    path: &Path,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = path.canonicalize()?;
    dprintln!(debug, "expanding: {}", path.display());
    let paths = path.read_dir()?;
    for path in paths {
        let path = path?.path();
        match path.is_file() {
            true => push_file(result, &path, debug)?,
            false => push_dir(result, &path, debug)?,
        }
    }

    Ok(())
}
