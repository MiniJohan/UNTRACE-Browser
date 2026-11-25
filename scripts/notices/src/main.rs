//! Third-party notices for UNTRACE's installer and About page.
//!
//! Rust: `cargo metadata` for the Windows target, from the `untrace` package through normal
//! dependencies only (build scripts and proc-macros are not shipped, but proc-macro crates
//! reached through normal edges are listed anyway, which is harmless). UNTRACE's own crates are
//! left out. UI: the npm production dependencies of `app/ui`, transitively.
//!
//! Each licence text is printed once, followed by every package it covers. Texts come from the
//! licence files in the packages as downloaded (nothing is fetched).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

const OUT: &str = "app/src-tauri/THIRD-PARTY-NOTICES.txt";

struct Package {
    name: String,
    version: String,
    license: String,
    repository: String,
    authors: String,
    dir: PathBuf,
}

fn licence_files(dir: &Path) -> Vec<(String, String)> {
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    let mut names: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
    names.sort();
    for p in names {
        let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_uppercase();
        let wanted = ["LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT", "UNLICENSE"]
            .iter()
            .any(|w| n.starts_with(w));
        if wanted && let Ok(t) = std::fs::read_to_string(&p) {
            let text = t.replace("\r\n", "\n").trim().to_string();
            if !text.is_empty() {
                out.push((p.file_name().unwrap().to_string_lossy().to_string(), text));
            }
        }
    }
    out
}

fn rust_packages(root: &Path) -> Vec<Package> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--filter-platform", "x86_64-pc-windows-msvc", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .output()
        .expect("cargo metadata");
    assert!(out.status.success(), "cargo metadata failed");
    let v: Value = serde_json::from_slice(&out.stdout).expect("metadata json");
    let members: BTreeSet<String> =
        v["workspace_members"].as_array().unwrap().iter().map(|m| m.as_str().unwrap().to_string()).collect();
    let pkgs: HashMap<String, &Value> =
        v["packages"].as_array().unwrap().iter().map(|p| (p["id"].as_str().unwrap().to_string(), p)).collect();
    let nodes: HashMap<String, &Value> = v["resolve"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["id"].as_str().unwrap().to_string(), n))
        .collect();
    let start = pkgs
        .values()
        .find(|p| p["name"] == "untrace")
        .map(|p| p["id"].as_str().unwrap().to_string())
        .expect("untrace package");
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([start]);
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id.clone()) {
            continue;
        }
        for d in nodes[&id]["deps"].as_array().unwrap() {
            let normal = d["dep_kinds"].as_array().unwrap().iter().any(|k| k["kind"].is_null());
            if normal {
                queue.push_back(d["pkg"].as_str().unwrap().to_string());
            }
        }
    }
    seen.into_iter()
        .filter(|id| !members.contains(id))
        .map(|id| {
            let p = pkgs[&id];
            Package {
                name: p["name"].as_str().unwrap().to_string(),
                version: p["version"].as_str().unwrap().to_string(),
                license: p["license"].as_str().unwrap_or("(none declared)").to_string(),
                repository: p["repository"].as_str().unwrap_or("").to_string(),
                authors: p["authors"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default(),
                dir: Path::new(p["manifest_path"].as_str().unwrap()).parent().unwrap().to_path_buf(),
            }
        })
        .collect()
}

fn npm_packages(ui: &Path) -> Vec<Package> {
    let read = |p: &Path| -> Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_default()).unwrap_or(Value::Null)
    };
    let root = read(&ui.join("package.json"));
    let mut queue: VecDeque<String> =
        root["dependencies"].as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let dir = ui.join("node_modules").join(&name);
        let pj = read(&dir.join("package.json"));
        if pj.is_null() {
            continue;
        }
        if let Some(deps) = pj["dependencies"].as_object() {
            queue.extend(deps.keys().cloned());
        }
        let repo = match &pj["repository"] {
            Value::String(s) => s.clone(),
            Value::Object(o) => o.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string(),
            _ => String::new(),
        };
        out.push(Package {
            name,
            version: pj["version"].as_str().unwrap_or("").to_string(),
            license: pj["license"].as_str().unwrap_or("(none declared)").to_string(),
            repository: repo,
            authors: match &pj["author"] {
                Value::String(a) => a.clone(),
                Value::Object(o) => o.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                _ => String::new(),
            },
            dir,
        });
    }
    out
}

fn render(rust: &[Package], npm: &[Package]) -> String {
    // Licence text → packages it covers. Packages without a licence file are listed apart.
    let mut by_text: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut without: BTreeSet<String> = BTreeSet::new();
    let mut all: Vec<&Package> = rust.iter().chain(npm).collect();
    all.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    for p in &all {
        let label = format!(
            "{} {} ({}){}",
            p.name,
            p.version,
            p.license,
            if p.repository.is_empty() { String::new() } else { format!(" {}", p.repository) }
        );
        let files = licence_files(&p.dir);
        if files.is_empty() {
            let by = if p.authors.is_empty() {
                String::new()
            } else {
                format!("\n    Copyright: {}", p.authors)
            };
            without.insert(format!("{label}{by}"));
        }
        for (_, text) in files {
            by_text.entry(text).or_default().insert(label.clone());
        }
    }
    let mut s = String::new();
    s.push_str("UNTRACE — third-party notices\n");
    s.push_str("==============================\n\n");
    s.push_str("UNTRACE's own code is licensed under the Mozilla Public License 2.0 (LICENSE).\n");
    s.push_str("It includes the following third-party software, each under its own licence.\n");
    s.push_str("The bundled block lists and their licences are listed in Settings and in\n");
    s.push_str("crates/untrace-filter/lists/NOTICE.md.\n\n");
    s.push_str(&format!(
        "{} Rust crates (Windows build, normal dependencies) and {} npm packages (UI).\n",
        rust.len(),
        npm.len()
    ));
    s.push_str("Generated by scripts/notices; do not edit by hand.\n");
    // Group texts so that the longest groups (most packages) come first.
    let mut groups: Vec<(String, BTreeSet<String>)> = by_text.into_iter().collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.1.iter().next().cmp(&b.1.iter().next())));
    for (text, pkgs) in groups {
        s.push_str("\n\n------------------------------------------------------------------------------\n");
        for p in &pkgs {
            s.push_str(&format!("* {p}\n"));
        }
        s.push_str("------------------------------------------------------------------------------\n\n");
        s.push_str(&text);
        s.push('\n');
    }
    if !without.is_empty() {
        s.push_str("\n\n------------------------------------------------------------------------------\n");
        s.push_str("Packages that ship no licence file. Their licence is the one each declares, whose\n");
        s.push_str("standard text appears above (MIT, Apache-2.0, BSD-3-Clause, MPL-2.0), with the\n");
        s.push_str("authors the package names as copyright holders:\n");
        s.push_str("------------------------------------------------------------------------------\n\n");
        for p in &without {
            s.push_str(&format!("* {p}\n"));
        }
    }
    s
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let root = root.canonicalize().expect("repository root");
    let rust = rust_packages(&root);
    let npm = npm_packages(&root.join("app").join("ui"));
    let text = render(&rust, &npm);
    let out = root.join(OUT);
    if std::env::args().any(|a| a == "--check") {
        let current = std::fs::read_to_string(&out).unwrap_or_default().replace("\r\n", "\n");
        if current != text {
            eprintln!("{OUT} is out of date: run cargo run --manifest-path scripts/notices/Cargo.toml");
            std::process::exit(1);
        }
        println!("{OUT} is up to date ({} crates, {} npm packages)", rust.len(), npm.len());
        return;
    }
    std::fs::write(&out, &text).expect("write notices");
    println!("wrote {OUT}: {} crates, {} npm packages, {} bytes", rust.len(), npm.len(), text.len());
}
