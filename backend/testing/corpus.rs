//! Shared helpers for corpus replay and fixed-artifact regression tests.

use std::fs;
use std::path::{Path, PathBuf};

/// Load every non-directory corpus entry under `dir`, sorted by path.
pub fn load_corpus_entries(dir: &Path) -> std::io::Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            entries.push((path.clone(), fs::read(&path)?));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

/// Assert that a committed corpus directory exists for a target.
pub fn assert_corpus_dir_exists(path: &Path) {
    assert!(
        path.is_dir(),
        "expected committed corpus directory to exist: {}",
        path.display()
    );
}
