//! Drift guard for the BLS-only migration (#1169): the crate seals to a BLS-G1 identity key
//! (slot `0x0010`), and the retired X25519 model (slot `0x0011`) must leave no trace in the source
//! or the SPEC. This test fails loudly if a stale X25519 reference is reintroduced.

use std::fs;
use std::path::Path;

/// Case-insensitive markers of the retired X25519 sealing model.
const RETIRED_MARKERS: &[&str] = &["x25519", "curve25519", "0x0011", "slot 0011"];

#[test]
fn no_retired_x25519_references_in_source_or_spec() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for relative in source_and_spec_files(root) {
        let contents = fs::read_to_string(&relative)
            .unwrap_or_default()
            .to_lowercase();
        for marker in RETIRED_MARKERS {
            if contents.contains(marker) {
                offenders.push(format!(
                    "{} contains retired marker {marker:?}",
                    relative.display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "retired X25519 references must be migrated to BLS-G1 (slot 0x0010):\n{}",
        offenders.join("\n")
    );
}

/// Every `.rs` under `src/` plus `SPEC.md` — the normative surfaces the migration must keep clean.
fn source_and_spec_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut files = vec![root.join("SPEC.md")];
    collect_rs(&root.join("src"), &mut files);
    files
}

fn collect_rs(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}
