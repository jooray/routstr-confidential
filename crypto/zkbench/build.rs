//! Records the commit the binary is built from as `CU_BUILD_COMMIT`, for
//! `--version`: the `CU_BUILD_COMMIT` environment variable when set (a
//! container build has no `.git`; pass it as a build argument), else the
//! checkout's `HEAD`, else `unknown`.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

fn main() {
    println!("cargo:rerun-if-env-changed=CU_BUILD_COMMIT");
    let given = std::env::var("CU_BUILD_COMMIT").ok().map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
    let commit = given.or_else(|| {
        // Built again when HEAD moves.
        let dir = std::path::PathBuf::from(git(&["rev-parse", "--absolute-git-dir"])?);
        // A worktree keeps its HEAD in its own directory, the refs in the common one.
        let common = git(&["rev-parse", "--path-format=absolute", "--git-common-dir"]).map(std::path::PathBuf::from).unwrap_or_else(|| dir.clone());
        let mut watch = vec![dir.join("HEAD"), common.join("packed-refs")];
        if let Some(r) = git(&["symbolic-ref", "-q", "HEAD"]) {
            watch.push(common.join(r));
        }
        for p in watch.iter().filter(|p| p.exists()) {
            println!("cargo:rerun-if-changed={}", p.display());
        }
        git(&["rev-parse", "--short=12", "HEAD"])
    });
    let commit = commit.filter(|c| c.chars().all(|ch| ch.is_ascii_alphanumeric() || "._-+".contains(ch)));
    println!("cargo:rustc-env=CU_BUILD_COMMIT={}", commit.as_deref().unwrap_or("unknown"));
}
