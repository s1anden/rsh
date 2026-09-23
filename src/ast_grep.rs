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
use std::collections::HashMap;
use std::collections::hash_map::Entry;
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

/// A validated config written to the temp dir; removed on drop.
pub struct TempConfig(PathBuf);

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Validated config copies for one command, keyed by their contents, so a
/// loop reuses one file instead of writing one per iteration.
pub type ConfigCache = HashMap<String, TempConfig>;

/// Resolve and validate the project config, then insert `-c <config>` into
/// args. The config is re-read and re-validated on every call; `cache` must
/// outlive the ast-grep process.
pub fn prepare_args(
    args: Vec<String>,
    working_dir: &Path,
    cache: &mut ConfigCache,
) -> Result<Vec<String>, String> {
    let Some(path) = find_config(working_dir)? else {
        check_needs_project(&args)?;
        return Ok(inject_config(args, "/dev/null"));
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let project_dir = path.parent().expect("config path has a parent");
    let sanitized =
        sanitize_config(&text, project_dir).map_err(|e| format!("{}: {}", path.display(), e))?;
    let temp = match cache.entry(sanitized) {
        Entry::Occupied(e) => e.into_mut(),
        Entry::Vacant(e) => {
            let temp = write_temp_config(e.key())?;
            e.insert(temp)
        }
    };
    let temp_str = temp
        .0
        .to_str()
        .ok_or_else(|| format!("non-UTF-8 temp path {}", temp.0.display()))?
        .to_string();
    Ok(inject_config(args, &temp_str))
}

/// Without a project, ast-grep errors on `test` and on `scan` with no rule
/// given. The injected empty config would make those silently succeed.
fn check_needs_project(args: &[String]) -> Result<(), String> {
    let needs_project = match args.first().map(String::as_str) {
        Some("test") => true,
        Some("scan") => !args[1..].iter().any(|a| {
            a == "--rule"
                || a.starts_with("--rule=")
                || a == "--inline-rules"
                || a.starts_with("--inline-rules=")
                || validator::short_cluster_flags("ast-grep", a).contains(&b'r')
        }),
        _ => false,
    };
    if needs_project {
        let hint = if args[0] == "scan" {
            " (pass -r <rule.yml> or --inline-rules)"
        } else {
            ""
        };
        return Err(format!(
            "'ast-grep {}' needs a project config, but no sgconfig.yml was found{}",
            args[0], hint
        ));
    }
    Ok(())
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
        let val = if key == "testConfigs" {
            sanitize_test_configs(val, project_dir)?
        } else if DIR_LIST_KEYS.contains(&key.as_str()) {
            let Value::Sequence(dirs) = val else {
                return Err(format!("ast-grep config '{}' must be a list", key));
            };
            let mut abs = Vec::with_capacity(dirs.len());
            for dir in dirs {
                let Value::String(dir) = dir else {
                    return Err(format!("ast-grep config '{}' entries must be strings", key));
                };
                abs.push(project_path(&dir, project_dir, &key)?);
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

/// Validate `dir` as a project-relative path and return it joined onto `project_dir`.
fn project_path(dir: &str, project_dir: &Path, key: &str) -> Result<Value, String> {
    validator::check_path_value(dir).map_err(|e| format!("ast-grep config '{}': {}", key, e))?;
    let joined = project_dir.join(dir);
    let joined = joined
        .to_str()
        .ok_or_else(|| format!("non-UTF-8 path in '{}'", key))?;
    Ok(Value::String(joined.to_string()))
}

/// `testConfigs` entries: `testDir` is resolved from the config's directory,
/// so it is made absolute; `snapshotDir` is relative to `testDir`, so it is
/// only validated.
fn sanitize_test_configs(val: Value, project_dir: &Path) -> Result<Value, String> {
    let Value::Sequence(entries) = val else {
        return Err("ast-grep config 'testConfigs' must be a list".to_string());
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let Value::Mapping(entry) = entry else {
            return Err("ast-grep config 'testConfigs' entries must be mappings".to_string());
        };
        let mut clean = Mapping::new();
        for (k, v) in entry {
            let (Value::String(k), Value::String(v)) = (&k, &v) else {
                return Err("ast-grep config 'testConfigs' entries must map strings".to_string());
            };
            let v = match k.as_str() {
                "testDir" => project_path(v, project_dir, "testConfigs.testDir")?,
                "snapshotDir" => {
                    validator::check_path_value(v)
                        .map_err(|e| format!("ast-grep config 'testConfigs.snapshotDir': {}", e))?;
                    Value::String(v.clone())
                }
                other => {
                    return Err(format!(
                        "ast-grep config 'testConfigs' key '{}' is not allowed",
                        other
                    ));
                }
            };
            clean.insert(Value::String(k.clone()), v);
        }
        out.push(Value::Mapping(clean));
    }
    Ok(Value::Sequence(out))
}

/// Placement only matters for clap accepting the command: ast-grep's config
/// pre-scan sees `-c` anywhere in argv.
fn inject_config(args: Vec<String>, config: &str) -> Vec<String> {
    let flag = ["-c".to_string(), config.to_string()];
    let first = args.first().map(String::as_str).unwrap_or("");
    let mut out = Vec::with_capacity(args.len() + 3);
    match first {
        "run" | "scan" | "outline" | "test" | "completions" => {
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
            (&["test"], &["test", "-c", "/dev/null"]),
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
        assert_eq!(v["testConfigs"][0]["testDir"], "/proj/tests");
        assert_eq!(check_config("").unwrap().trim(), "{}");
    }

    #[test]
    fn test_sanitize_config_accepts_real_project_configs() {
        let rules = check_config("ruleDirs:\n- rules\ntestConfigs:\n- testDir: tests\n").unwrap();
        let v: Value = serde_yaml::from_str(&rules).unwrap();
        assert_eq!(v["ruleDirs"][0], "/proj/rules");
        assert_eq!(v["testConfigs"][0]["testDir"], "/proj/tests");

        let vue = r#"languageGlobs:
  html:
    - "**/*.vue"
languageInjections:
  - hostLanguage: html
    injected: typescript
    rule:
      kind: raw_text
      pattern: $CONTENT
      inside:
        kind: script_element
        has:
          kind: start_tag
          has:
            kind: attribute
            regex: "^lang\\s*=\\s*['\"]?(ts|typescript)['\"]?$"
"#;
        let v: Value = serde_yaml::from_str(&check_config(vue).unwrap()).unwrap();
        let original: Value = serde_yaml::from_str(vue).unwrap();
        // Data keys must round-trip unchanged, regex escapes included.
        assert_eq!(v["languageInjections"], original["languageInjections"]);
        assert_eq!(v["languageGlobs"], original["languageGlobs"]);
    }

    #[test]
    fn test_sanitize_config_keeps_snapshot_dir_relative() {
        let out =
            check_config("testConfigs:\n  - testDir: tests\n    snapshotDir: snaps\n").unwrap();
        let v: Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["testConfigs"][0]["testDir"], "/proj/tests");
        assert_eq!(v["testConfigs"][0]["snapshotDir"], "snaps");
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_needs_project_without_config() {
        for args in [
            &["test"][..],
            &["test", "--skip-snapshot-tests"],
            &["scan"],
            &["scan", "--json"],
            &["scan", "--filter", "x"],
        ] {
            let err = check_needs_project(&strings(args)).expect_err(&format!("{:?}", args));
            assert!(err.contains("needs a project config"), "{}", err);
        }
        for args in [
            &["scan", "-r", "r.yml"][..],
            &["scan", "-rr.yml"],
            &["scan", "-Ur", "r.yml"],
            &["scan", "--rule", "r.yml"],
            &["scan", "--rule=r.yml"],
            &["scan", "--inline-rules", "id: x"],
            &["scan", "--inline-rules=id: x"],
            &["run", "-p", "x"],
            &["-p", "x"],
            &["outline", "a.rs"],
            &["--version"],
            &[],
        ] {
            assert!(check_needs_project(&strings(args)).is_ok(), "{:?}", args);
        }
    }

    #[test]
    fn test_prepare_args_reuses_copy_for_same_config() {
        let dir = std::env::temp_dir().join("rsh_unit_sgconfig_cache");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sgconfig.yml"), "ruleDirs: [rules]\n").unwrap();
        let mut cache = ConfigCache::new();
        let a = prepare_args(strings(&["run", "-p", "x"]), &dir, &mut cache).unwrap();
        let b = prepare_args(strings(&["run", "-p", "y"]), &dir, &mut cache).unwrap();
        assert_eq!(a[2], b[2], "same config should reuse the copy");
        assert_eq!(cache.len(), 1);

        // An edit is re-validated and gets its own copy.
        std::fs::write(dir.join("sgconfig.yml"), "ruleDirs: [other]\n").unwrap();
        let c = prepare_args(strings(&["run", "-p", "x"]), &dir, &mut cache).unwrap();
        assert_ne!(a[2], c[2]);
        std::fs::write(dir.join("sgconfig.yml"), "customLanguages: {}\n").unwrap();
        assert!(prepare_args(strings(&["run", "-p", "x"]), &dir, &mut cache).is_err());

        let paths: Vec<_> = cache.values().map(|t| t.0.clone()).collect();
        drop(cache);
        assert!(paths.iter().all(|p| !p.exists()));
        std::fs::remove_dir_all(&dir).unwrap();
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
            ("testConfigs: [{testDir: /etc}]\n", "absolute path"),
            (
                "testConfigs: [{testDir: t, snapshotDir: ../s}]\n",
                "path traversal",
            ),
            (
                "testConfigs: [{testDir: t, other: x}]\n",
                "'other' is not allowed",
            ),
            ("testConfigs: [tests]\n", "must be mappings"),
            ("testConfigs: {testDir: t}\n", "must be a list"),
            ("testConfigs: [{testDir: [t]}]\n", "must map strings"),
            ("ruleDirs: [\n", "could not be parsed"),
        ] {
            let err = check_config(bad).expect_err(bad);
            assert!(err.contains(expected), "{:?}: {}", bad, err);
        }
    }
}
