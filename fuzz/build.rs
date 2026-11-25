// Windows/MSVC without the AddressSanitizer runtime: define the coverage-section boundaries
// libFuzzer needs (see sancov_win_sections.c).
fn main() {
    println!("cargo:rerun-if-changed=sancov_win_sections.c");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        cc::Build::new()
            .file("sancov_win_sections.c")
            .compile("untrace_sancov_win_sections");
    }
}
