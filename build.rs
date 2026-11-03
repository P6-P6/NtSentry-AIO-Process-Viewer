//! Embeds the icon and version details (assets/app.rc) into ntsentry.exe.
//! Needs rc.exe from the Windows SDK, which build.ps1 puts on PATH. Without it
//! the build still succeeds, just without an embedded icon.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/app.rc");
    println!("cargo:rerun-if-changed=assets/ntsentry.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("app.res");
    let status = Command::new("rc.exe")
        .current_dir("assets")
        .arg("/nologo")
        .arg(format!("/fo{}", out.display()))
        .arg("app.rc")
        .status();
    match status {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg-bins={}", out.display()),
        Ok(s) => println!("cargo:warning=rc.exe failed ({s}); ntsentry.exe will have no embedded icon"),
        Err(_) => println!("cargo:warning=rc.exe not found (run build.ps1); ntsentry.exe will have no embedded icon"),
    }
}
