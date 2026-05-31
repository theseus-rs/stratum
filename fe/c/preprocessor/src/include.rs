//! Resolution of `#include` directives to source text.

use crate::alloc_prelude::*;
use stratum_utils::HashMap;

#[cfg(any(test, feature = "std"))]
use std::path::{Path, PathBuf};

/// A resolved include: a display name plus the file's contents.
#[derive(Debug, Clone)]
pub struct ResolvedInclude {
    /// The name to register in the source map (typically the full path).
    pub name: String,
    /// The file's text.
    pub contents: String,
}

/// Resolves `#include` targets to source text.
///
/// The preprocessor is decoupled from the filesystem through this trait so it can be driven
/// against in-memory fixtures in tests and real files in production.
pub trait IncludeResolver {
    /// Resolves an include.
    ///
    /// * `name` is the spelling between the quotes or angle brackets.
    /// * `angled` is `true` for `<...>` includes and `false` for `"..."` includes.
    /// * `current` is the display name of the file containing the directive, if known,
    ///   used to resolve quoted includes relative to it.
    ///
    /// Returns `None` if the include cannot be found.
    fn resolve(
        &mut self,
        name: &str,
        angled: bool,
        current: Option<&str>,
    ) -> Option<ResolvedInclude>;
}

/// An [`IncludeResolver`] backed by an in-memory map, primarily for tests.
#[derive(Debug, Default, Clone)]
pub struct MapIncludeResolver {
    files: HashMap<String, String>,
}

impl MapIncludeResolver {
    /// Creates an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: HashMap::default(),
        }
    }

    /// Adds a virtual file addressable by `name`.
    #[must_use]
    pub fn with_file(mut self, name: impl Into<String>, contents: impl Into<String>) -> Self {
        self.files.insert(name.into(), contents.into());
        self
    }

    /// Inserts a virtual file addressable by `name`.
    pub fn insert(&mut self, name: impl Into<String>, contents: impl Into<String>) {
        self.files.insert(name.into(), contents.into());
    }
}

impl IncludeResolver for MapIncludeResolver {
    fn resolve(
        &mut self,
        name: &str,
        _angled: bool,
        _current: Option<&str>,
    ) -> Option<ResolvedInclude> {
        self.files.get(name).map(|contents| ResolvedInclude {
            name: name.to_string(),
            contents: contents.clone(),
        })
    }
}

/// An [`IncludeResolver`] that reads from the filesystem using a list of search directories.
///
/// Quoted includes are first looked up relative to the including file's directory, then via
/// the search path; angled includes use the search path only.
#[cfg(any(test, feature = "std"))]
#[derive(Debug, Default, Clone)]
pub struct FsIncludeResolver {
    search_paths: Vec<PathBuf>,
}

#[cfg(any(test, feature = "std"))]
impl FsIncludeResolver {
    /// Creates a resolver with the given system search directories.
    #[must_use]
    pub fn new(search_paths: Vec<PathBuf>) -> Self {
        Self { search_paths }
    }

    /// Appends a search directory.
    pub fn push_search_path(&mut self, path: impl Into<PathBuf>) {
        self.search_paths.push(path.into());
    }

    fn read(path: &Path) -> Option<ResolvedInclude> {
        let contents = std::fs::read_to_string(path).ok()?;
        Some(ResolvedInclude {
            name: path.to_string_lossy().into_owned(),
            contents,
        })
    }
}

#[cfg(any(test, feature = "std"))]
impl IncludeResolver for FsIncludeResolver {
    fn resolve(
        &mut self,
        name: &str,
        angled: bool,
        current: Option<&str>,
    ) -> Option<ResolvedInclude> {
        if !angled && let Some(parent) = current.map(Path::new).and_then(Path::parent) {
            let candidate = parent.join(name);
            if let Some(found) = Self::read(&candidate) {
                return Some(found);
            }
        }
        for dir in &self.search_paths {
            let candidate = dir.join(name);
            if let Some(found) = Self::read(&candidate) {
                return Some(found);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{FsIncludeResolver, IncludeResolver, MapIncludeResolver};
    use crate::alloc_prelude::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_dir() -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("stratum-include-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn map_resolver_finds_file() {
        let mut resolver = MapIncludeResolver::new().with_file("a.h", "int a;");
        let outcome = resolver.resolve("a.h", false, None);
        assert_eq!(outcome.map(|r| r.contents), Some("int a;".to_string()));
    }

    #[test]
    fn map_resolver_missing_file() {
        let mut resolver = MapIncludeResolver::new();
        assert!(resolver.resolve("missing.h", true, None).is_none());
    }

    #[test]
    fn map_resolver_insert_adds_file() {
        let mut resolver = MapIncludeResolver::new();
        resolver.insert("b.h", "int b;");
        let found = resolver.resolve("b.h", false, Some("main.c")).unwrap();
        assert_eq!(found.name, "b.h");
        assert_eq!(found.contents, "int b;");
    }

    #[test]
    fn fs_resolver_checks_current_directory_for_quoted_include() {
        let dir = fixture_dir();
        let current = dir.join("main.c");
        let header = dir.join("local.h");
        fs::write(&current, "").unwrap();
        fs::write(&header, "int local;").unwrap();

        let mut resolver = FsIncludeResolver::new(Vec::new());
        let found = resolver
            .resolve("local.h", false, current.to_str())
            .unwrap();
        assert_eq!(found.contents, "int local;");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fs_resolver_uses_search_paths_and_reports_missing() {
        let dir = fixture_dir();
        let header = dir.join("system.h");
        fs::write(&header, "int system;").unwrap();

        let mut resolver = FsIncludeResolver::new(Vec::new());
        resolver.push_search_path(&dir);
        let found = resolver.resolve("system.h", true, None).unwrap();
        assert_eq!(found.contents, "int system;");
        assert!(resolver.resolve("missing.h", true, None).is_none());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fs_resolver_falls_back_to_search_path_for_quoted_include() {
        let root = fixture_dir();
        let current_dir = root.join("current");
        let search_dir = root.join("search");
        fs::create_dir_all(&current_dir).unwrap();
        fs::create_dir_all(&search_dir).unwrap();
        let current = current_dir.join("main.c");
        let header = search_dir.join("fallback.h");
        fs::write(&current, "").unwrap();
        fs::write(&header, "int fallback;").unwrap();

        let mut resolver = FsIncludeResolver::new(vec![search_dir.clone()]);
        let found = resolver
            .resolve("fallback.h", false, current.to_str())
            .unwrap();
        assert_eq!(found.contents, "int fallback;");

        fs::remove_dir_all(root).unwrap();
    }
}
