/// ast-grep project config handling.
///
/// ast-grep auto-discovers sgconfig.yml from its cwd upward and, before parsing
/// args, dlopen()s any `customLanguages.*.libraryPath` in it, i.e. arbitrary
/// native code. It skips discovery when argv contains `-c <file>`, so rsh runs
/// the same discovery itself, validates what it finds, and passes ast-grep a
/// private copy of the validated config (`/dev/null` when there is none). The
/// copy matters: if ast-grep re-read the project file, a concurrent writer
/// (`ast-grep -U` in another pipeline stage or rsh process) could swap in
/// `customLanguages` after the check. User `-c` is blocked in the validator.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_yaml::{Mapping, Value};

use crate::validator;

/// Top-level sgconfig keys that are plain data. Anything else, including
/// `customLanguages` and any key ast-grep adds later, is rejected.
const ALLOWED_KEYS: &[&str] = &[
    "ruleDirs",
    "utilDirs",
    "testConfigs",
    "languageGlobs",
    "languageInjections",
];

/// Keys whose entries are directories ast-grep reads relative to the config's
/// directory. The private copy lives elsewhere, so these are made absolute.
const DIR_LIST_KEYS: &[&str] = &["ruleDirs", "utilDirs"];

/// Dropped from the copy: only `ast-grep test` (blocked) reads it.
const DROPPED_KEYS: &[&str] = &["testConfigs"];

/// A validated config written to the temp dir; removed on drop.
pub struct TempConfig(PathBuf);

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Resolve and validate the project config, then insert `-c <config>` into
/// args. Keep the returned TempConfig alive until ast-grep exits.
pub fn prepare_args(
    args: Vec<String>,
    working_dir: &Path,
) -> Result<(Vec<String>, Option<TempConfig>), String> {
    let Some(path) = find_config(working_dir)? else {
        return Ok((inject_config(args, "/dev/null"), None));
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let project_dir = path.parent().expect("config path has a parent");
    let sanitized =
        sanitize_config(&text, project_dir).map_err(|e| format!("{}: {}", path.display(), e))?;
    let temp = write_temp_config(&sanitized)?;
    let temp_str = temp
        .0
        .to_str()
        .ok_or_else(|| format!("non-UTF-8 temp path {}", temp.0.display()))?
        .to_string();
    Ok((inject_config(args, &temp_str), Some(temp)))
}

fn write_temp_config(contents: &str) -> Result<TempConfig, String> {
    use std::io::Write;
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "rsh-sgconfig-{}-{}-{}.yml",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        nanos
    ));
    // create_new refuses to follow a pre-planted file or symlink at this path.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| format!("cannot create ast-grep config copy: {}", e))?;
    let temp = TempConfig(path);
    file.write_all(contents.as_bytes())
        .map_err(|e| format!("cannot write ast-grep config copy: {}", e))?;
    Ok(temp)
}

/// Mirror ast-grep's discovery: nearest ancestor of the (canonical) cwd with
/// sgconfig.yml, else sgconfig.yaml.
fn find_config(working_dir: &Path) -> Result<Option<PathBuf>, String> {
    let dir = working_dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve working directory: {}", e))?;
    for ancestor in dir.ancestors() {
        for name in ["sgconfig.yml", "sgconfig.yaml"] {
            let path = ancestor.join(name);
            if path.exists() {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

/// Validate a project config and return the YAML to hand ast-grep instead.
fn sanitize_config(text: &str, project_dir: &Path) -> Result<String, String> {
    let value: Value = serde_yaml::from_str(text)
        .map_err(|e| format!("ast-grep config could not be parsed: {}", e))?;
    let map = match value {
        Value::Null => Mapping::new(),
        Value::Mapping(map) => map,
        _ => return Err("ast-grep config must be a mapping".to_string()),
    };
    let mut out = Mapping::new();
    for (key, val) in map {
        let key = match key {
            Value::String(k) if ALLOWED_KEYS.contains(&k.as_str()) => k,
            Value::String(k) if k == "customLanguages" => {
                return Err(
                    "ast-grep config with 'customLanguages' is not allowed (loads native libraries)"
                        .to_string(),
                );
            }
            other => {
                return Err(format!(
                    "ast-grep config key {:?} is not allowed",
                    serde_yaml::to_string(&other).unwrap_or_default().trim()
                ));
            }
        };
        if DROPPED_KEYS.contains(&key.as_str()) {
            continue;
        }
        let val = if DIR_LIST_KEYS.contains(&key.as_str()) {
            let Value::Sequence(dirs) = val else {
                return Err(format!("ast-grep config '{}' must be a list", key));
            };
            let mut abs = Vec::with_capacity(dirs.len());
            for dir in dirs {
                let Value::String(dir) = dir else {
                    return Err(format!("ast-grep config '{}' entries must be strings", key));
                };
                validator::check_path_value(&dir)
                    .map_err(|e| format!("ast-grep config '{}': {}", key, e))?;
                let joined = project_dir.join(&dir);
                let joined = joined
                    .to_str()
                    .ok_or_else(|| format!("non-UTF-8 path in '{}'", key))?;
                abs.push(Value::String(joined.to_string()));
            }
            Value::Sequence(abs)
        } else {
            val
        };
        out.insert(Value::String(key), val);
    }
    serde_yaml::to_string(&Value::Mapping(out))
        .map_err(|e| format!("cannot serialize ast-grep config: {}", e))
}

/// Placement only matters for clap accepting the command: ast-grep's config
/// pre-scan sees `-c` anywhere in argv.
fn inject_config(args: Vec<String>, config: &str) -> Vec<String> {
    let flag = ["-c".to_string(), config.to_string()];
    let first = args.first().map(String::as_str).unwrap_or("");
    let mut out = Vec::with_capacity(args.len() + 3);
    match first {
        "run" | "scan" | "outline" | "completions" => {
            out.push(args[0].clone());
            out.extend(flag);
            out.extend_from_slice(&args[1..]);
        }
        // Default-run form (`ast-grep -p x`) rejects -c, so make `run` explicit.
        f if f.starts_with('-') && !matches!(f, "-h" | "--help" | "-V" | "--version") => {
            out.push("run".to_string());
            out.extend(flag);
            out.extend(args);
        }
        _ => {
            out.extend(flag);
            out.extend(args);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inject(args: &[&str]) -> Vec<String> {
        inject_config(args.iter().map(|s| s.to_string()).collect(), "/dev/null")
    }

    #[test]
    fn test_inject_config_placement() {
        let cases: &[(&[&str], &[&str])] = &[
            (&["run", "-p", "x"], &["run", "-c", "/dev/null", "-p", "x"]),
            (
                &["scan", "-r", "r.yml"],
                &["scan", "-c", "/dev/null", "-r", "r.yml"],
            ),
            (
                &["outline", "a.rs"],
                &["outline", "-c", "/dev/null", "a.rs"],
            ),
            (
                &["completions", "zsh"],
                &["completions", "-c", "/dev/null", "zsh"],
            ),
            (
                &["-p", "x", "."],
                &["run", "-c", "/dev/null", "-p", "x", "."],
            ),
            (&["--help"], &["-c", "/dev/null", "--help"]),
            (&["-V"], &["-c", "/dev/null", "-V"]),
            (&["help", "run"], &["-c", "/dev/null", "help", "run"]),
            (&[], &["-c", "/dev/null"]),
        ];
        for (input, expected) in cases {
            assert_eq!(inject(input), *expected, "input: {:?}", input);
        }
    }

    fn check_config(text: &str) -> Result<String, String> {
        sanitize_config(text, Path::new("/proj"))
    }

    #[test]
    fn test_sanitize_config_keeps_data_and_absolutizes_dirs() {
        let out = check_config(
            "ruleDirs:\n  - rules\n  - more/rules\nutilDirs: [utils]\ntestConfigs:\n  - testDir: tests\nlanguageGlobs:\n  html: ['*.vue']\nlanguageInjections: []\n",
        )
        .unwrap();
        let v: Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(
            v["ruleDirs"],
            serde_yaml::from_str::<Value>("[/proj/rules, /proj/more/rules]").unwrap()
        );
        assert_eq!(
            v["utilDirs"],
            serde_yaml::from_str::<Value>("[/proj/utils]").unwrap()
        );
        assert_eq!(v["languageGlobs"]["html"][0], "*.vue");
        assert!(v.get("languageInjections").is_some());
        assert!(v.get("testConfigs").is_none());
        assert_eq!(check_config("").unwrap().trim(), "{}");
    }

    #[test]
    fn test_temp_config_removed_on_drop() {
        let temp = write_temp_config("ruleDirs: []\n").unwrap();
        let path = temp.0.clone();
        assert!(path.exists());
        drop(temp);
        assert!(!path.exists());
    }

    #[test]
    fn test_check_config_rejects() {
        for (bad, expected) in [
            (
                "customLanguages:\n  evil:\n    libraryPath: evil.so\n",
                "customLanguages",
            ),
            ("\"customLanguages\": {}\n", "customLanguages"),
            ("ruleDirs: []\ncustomLanguages: {}\n", "customLanguages"),
            ("!tag customLanguages: {}\n", "not allowed"),
            ("? [customLanguages]\n: {}\n", "not allowed"),
            ("somethingNew: 1\n", "not allowed"),
            ("<<: {customLanguages: {}}\n", "not allowed"),
            ("ruleDirs: [/etc]\n", "absolute path"),
            ("utilDirs: [../outside]\n", "path traversal"),
            ("ruleDirs: rules\n", "must be a list"),
            ("ruleDirs: [1]\n", "must be strings"),
            ("- ruleDirs\n", "must be a mapping"),
            ("ruleDirs: [a]\nruleDirs: [b]\n", "could not be parsed"),
            ("ruleDirs: [\n", "could not be parsed"),
        ] {
            let err = check_config(bad).expect_err(bad);
            assert!(err.contains(expected), "{:?}: {}", bad, err);
        }
    }
}
