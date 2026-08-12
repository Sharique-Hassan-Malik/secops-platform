/*
 * main.rs  —  ZIP Bomb Detector (Rust)
 * Build:  cargo build --release
 * Usage:  ./zipbomb_detector <file.zip> [--policy strict|paranoid|relaxed] [--json]
 *         ./zipbomb_detector --dir <directory> [--policy strict] [--json]
 */

mod policy;
mod formats;
mod scanner;
mod types;

use std::path::Path;
use policy::ScanPolicy;
use scanner::{Scanner, detect_format};
use formats::{scan_gzip, scan_bzip2, scan_tar, scan_7z, scan_xz, scan_rar, scan_zstd};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file.zip> [--policy strict|paranoid|relaxed] [--json]", args[0]);
        eprintln!("       {} --dir <directory> [--policy ...] [--json]", args[0]);
        std::process::exit(1);
    }

    let mut policy     = ScanPolicy::default();
    let mut json_out   = false;
    let mut dir_mode: Option<String> = None;
    let mut files      = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json"   => json_out = true,
            "--policy" => {
                i += 1;
                if i < args.len() {
                    policy = match args[i].as_str() {
                        "strict"   => ScanPolicy::strict(),
                        "paranoid" => ScanPolicy::paranoid(),
                        "relaxed"  => ScanPolicy::relaxed(),
                        _          => ScanPolicy::default(),
                    };
                }
            }
            "--dir" => {
                i += 1;
                if i < args.len() { dir_mode = Some(args[i].clone()); }
            }
            arg if !arg.starts_with("--") => files.push(arg.to_string()),
            _ => {}
        }
        i += 1;
    }

    let scanner   = Scanner::new(policy.clone());
    let mut exit_code = 0;

    if let Some(dir) = dir_mode {
        for result in scanner.scan_directory(Path::new(&dir)) {
            print_result(&result, json_out);
            if result.is_threat { exit_code = 1; }
        }
    } else {
        for file in &files {
            let fmt = detect_format(Path::new(file));
        eprintln!("Format: {fmt}");
        let result = match fmt {
            "gzip"  => scan_gzip(Path::new(file), &policy),
            "bzip2" => scan_bzip2(Path::new(file), &policy),
            "tar" | "tar.gz" | "tar.bzip2" | "tar.xz"
                     => scan_tar(Path::new(file), &policy),
            "7z"    => scan_7z(Path::new(file), &policy),
            "xz"    => scan_xz(Path::new(file), &policy),
            "rar" | "rar4" | "rar5"
                     => scan_rar(Path::new(file), &policy),
            "zstd"  => scan_zstd(Path::new(file), &policy),
            _        => scanner.scan(Path::new(file), 0),  // zip + unknown
        };
            print_result(&result, json_out);
            if result.is_threat { exit_code = 1; }
        }
    }

    std::process::exit(exit_code);
}

fn print_result(result: &types::ScanResult, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(result).unwrap_or_default());
    } else {
        result.print_summary();
    }
}
