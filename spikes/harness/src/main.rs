//! UNTRACE Milestone 0 spike harness. Throwaway code: answers feasibility questions,
//! writes machine-readable results to `spikes/results/<spike>.json`.

mod fixture;
mod host;
mod proxy;
mod pump;
mod s2;
mod s3;
mod s5;
mod s6;
mod s7;
mod s4;
mod kit;
mod m5;
mod m6;
mod m8;

use std::path::PathBuf;

use windows::Win32::{
    System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED},
    UI::HiDpi::{SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2},
};

pub fn note(s: &str) {
    eprintln!("[spike] {s}");
}

pub fn spikes_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

pub fn data_dir() -> PathBuf {
    spikes_dir().join("data")
}

/// Root for WebView2 user-data folders. Kept short (MAX_PATH): set UNTRACE_SPIKE_UDF.
pub fn udf_root() -> PathBuf {
    std::env::var_os("UNTRACE_SPIKE_UDF").map(PathBuf::from).unwrap_or_else(|| data_dir().join("udf"))
}

/// A fresh, unique WebView2 user-data folder for one experiment.
pub fn fresh_udf(name: &str) -> PathBuf {
    let p = udf_root().join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("udf dir");
    p
}

fn main() {
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok().expect("COM init");
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let which = std::env::args().nth(1).unwrap_or_default();
    let result = match which.as_str() {
        "s2" => s2::run(),
        "s3" => s3::run(),
        "s5" => s5::run(),
        "s6" => s6::run(),
        "s4" => s4::run(),
        "s7" => s7::run(),
        "m5" => m5::run(),
        "m6" => m6::run(),
        "m8" => m8::run(),
        _ => {
            eprintln!("usage: untrace-spike-harness <s2|s3|s4|s5|s6|s7|m5|m6|m8 [only-runs-starting-with]>");
            std::process::exit(2);
        }
    };
    // A filtered M8 run gets its own file, so it never overwrites the full run.
    let name = match std::env::args().nth(2) {
        Some(f) if which == "m8" => format!("m8-{f}"),
        _ => which.clone(),
    };
    let out = spikes_dir().join("results").join(format!("{name}.json"));
    let text = serde_json::to_string_pretty(&result).expect("json");
    std::fs::write(&out, &text).expect("write results");
    println!("{text}");
    note(&format!("results written to {}", out.display()));
}


