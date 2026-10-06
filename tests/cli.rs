//! End-to-end CLI flows against scratch stores. Hermetic by construction:
//! `EST_VAULT_DIR`/`EST_VAULT_SCHEMA` point at temp dirs, every stored
//! secret is `--plain` (no crypto, no Keychain), and `EST_VAULT_KEYCHAIN`
//! names a bogus service, so key lookups deterministically miss instead
//! of ever touching the real Keychain — even if an implementation
//! regresses. Encrypted paths are pinned in the lib tests and the
//! conformance vectors. `init` can only be tested for refusal: a real
//! init provisions a Keychain key, so tests build the store skeleton
//! (directory + `.salt`) directly.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("est-vault-cli-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Vault {
    dir: PathBuf,
}

impl Vault {
    fn new(name: &str) -> Self {
        Vault { dir: scratch(name) }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_est-vault"));
        cmd.args(args)
            .env("EST_VAULT_DIR", self.dir.join("store"))
            .env("EST_VAULT_SCHEMA", self.dir.join("schema.toml"))
            .env(
                "EST_VAULT_KEYCHAIN",
                format!("est-vault-test-missing-{}", std::process::id()),
            )
            .current_dir(&self.dir);
        cmd
    }

    /// Without the keychain override: only for tests asserting defaults.
    fn cmd_raw(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_est-vault"));
        cmd.args(args)
            .env("EST_VAULT_DIR", self.dir.join("store"))
            .env("EST_VAULT_SCHEMA", self.dir.join("schema.toml"))
            .current_dir(&self.dir);
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    fn run_stdin(&self, args: &[&str], input: &str) -> Output {
        use std::io::Write;
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// The store skeleton `init` would make, minus the Keychain key.
    fn skeleton(&self) {
        let store = self.dir.join("store");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join(".salt"), b"testing").unwrap();
    }

    fn stdout(&self, out: &Output) -> String {
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    fn stderr(&self, out: &Output) -> String {
        String::from_utf8_lossy(&out.stderr).to_string()
    }
}

fn parse_json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn where_shows_resolved_paths() {
    let vault = Vault::new("where");
    let out = vault.cmd_raw(&["where"]).output().unwrap();
    assert!(out.status.success());
    let text = vault.stdout(&out);
    assert!(text.contains("store:"), "{text}");
    assert!(text.contains("keychain:  est-vault"), "{text}");
    let value = parse_json(&vault.cmd_raw(&["where", "--json"]).output().unwrap());
    assert_eq!(value["ok"], true);
    assert_eq!(value["v"], 1);
    assert_eq!(value["keychain"], "est-vault");
}

#[test]
fn init_refuses_an_existing_store_without_touching_the_keychain() {
    let vault = Vault::new("init-refuse");
    vault.skeleton();
    let out = vault.run(&["init"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        vault.stderr(&out).contains("already lives"),
        "{}",
        vault.stderr(&out)
    );
}

#[test]
fn add_plain_and_get_roundtrip() {
    let vault = Vault::new("roundtrip");
    vault.skeleton();
    let out = vault.run(&["add", "demo:key:app", "--plain", "--value", "s3cret"]);
    assert!(out.status.success(), "{}", vault.stderr(&out));
    assert!(vault.stdout(&out).contains("added DEMO:KEY:APP"));
    let out = vault.run(&["get", "DEMO:KEY:APP"]);
    assert!(out.status.success());
    assert_eq!(vault.stdout(&out), "s3cret");
}

#[test]
fn add_reads_stdin_and_strips_the_newline() {
    let vault = Vault::new("stdin");
    vault.skeleton();
    let out = vault.run_stdin(&["add", "T:K:IN", "--plain"], "piped-value\n");
    assert!(out.status.success(), "{}", vault.stderr(&out));
    let out = vault.run(&["get", "T:K:IN"]);
    assert_eq!(vault.stdout(&out), "piped-value");
}

#[test]
fn add_refuses_overwrite_until_replace() {
    let vault = Vault::new("replace");
    vault.skeleton();
    assert!(
        vault
            .run(&["add", "T:K:R", "--plain", "--value", "one"])
            .status
            .success()
    );
    let out = vault.run(&["add", "T:K:R", "--plain", "--value", "two"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(vault.stderr(&out).contains("--replace"));
    let out = vault.run(&["add", "T:K:R", "--plain", "--value", "two", "--replace"]);
    assert!(out.status.success());
    assert_eq!(vault.stdout(&vault.run(&["get", "T:K:R"])), "two");
}

#[test]
fn add_validates_and_needs_a_store() {
    let vault = Vault::new("add-errors");
    let out = vault.run(&["add", "bogus", "--plain", "--value", "x"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(vault.stderr(&out).contains("bad address"));
    let out = vault.run(&["add", "T:K:NOSTORE", "--plain", "--value", "x"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(vault.stderr(&out).contains("no store at"));
    let out = vault.run(&["add", "--plain", "--value", "x"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn add_encrypted_needs_a_key() {
    let vault = Vault::new("add-enc");
    vault.skeleton();
    let out = vault.run(&["add", "T:K:ENC", "--value", "x"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(vault.stderr(&out).contains("no key in Keychain"));
}

#[test]
fn list_shows_text_and_json() {
    let vault = Vault::new("list");
    vault.skeleton();
    vault.run(&["add", "B:K:2", "--plain", "--value", "x"]);
    vault.run(&["add", "A:K:1", "--plain", "--value", "x"]);
    let out = vault.run(&["list"]);
    assert_eq!(vault.stdout(&out), "A:K:1\nB:K:2\n");
    let out = vault.run(&["list", "a:"]);
    assert_eq!(vault.stdout(&out), "A:K:1\n");
    let value = parse_json(&vault.run(&["list", "--json"]));
    assert_eq!(value["ok"], true);
    assert_eq!(value["addresses"][0]["storage"], "plain");
    assert_eq!(value["addresses"].as_array().unwrap().len(), 2);
}

#[test]
fn get_missing_and_out_file() {
    let vault = Vault::new("get");
    vault.skeleton();
    let out = vault.run(&["get", "T:K:NOPE"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(vault.stderr(&out).contains("no secret T:K:NOPE"));
    vault.run(&["add", "T:K:OUT", "--plain", "--value", "bytes"]);
    let target = vault.dir.join("value.txt");
    let target_str = target.to_string_lossy().into_owned();
    let out = vault.run(&["get", "T:K:OUT", "--out", &target_str]);
    assert!(out.status.success());
    assert_eq!(std::fs::read(&target).unwrap(), b"bytes");
}

#[test]
fn remove_asks_then_deletes_with_yes() {
    let vault = Vault::new("remove");
    vault.skeleton();
    vault.run(&["add", "T:K:DEL", "--plain", "--value", "x"]);
    let out = vault.run_stdin(&["remove", "T:K:DEL"], "");
    assert_eq!(out.status.code(), Some(1));
    assert!(vault.stderr(&out).contains("not deleted"));
    assert!(vault.dir.join("store/T/K/DEL.plain").is_file());
    let out = vault.run(&["remove", "T:K:DEL", "--yes"]);
    assert!(out.status.success());
    assert!(vault.stdout(&out).contains("deleted T:K:DEL"));
    assert!(!vault.dir.join("store/T/K/DEL.plain").exists());
    let out = vault.run(&["remove", "T:K:DEL", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn templates_roundtrip_with_use_guard() {
    let vault = Vault::new("templates");
    vault.skeleton();
    let value = parse_json(&vault.run(&["templates", "--json"]));
    assert_eq!(value["templates"].as_array().unwrap().len(), 0);
    let out = vault.run(&["template", "add", "ACME:KEY:<APP>", "--hint", "the key"]);
    assert!(out.status.success(), "{}", vault.stderr(&out));
    assert!(
        vault
            .stdout(&vault.run(&["templates"]))
            .contains("ACME:KEY:<APP>")
    );
    vault.run(&["add", "ACME:KEY:WEB", "--plain", "--value", "x"]);
    let out = vault.run(&["template", "delete", "ACME", "KEY"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(vault.stderr(&out).contains("still use"));
    vault.run(&["remove", "ACME:KEY:WEB", "--yes"]);
    let out = vault.run(&["template", "delete", "ACME", "KEY"]);
    assert!(out.status.success());
    let value = parse_json(&vault.run(&["templates", "--json"]));
    assert_eq!(value["templates"].as_array().unwrap().len(), 0);
}

#[test]
fn schema_guides_add_shape() {
    let vault = Vault::new("schema-add");
    vault.skeleton();
    vault.run(&["template", "add", "ACME:KEY:<APP>"]);
    let out = vault.run(&["add", "ACME:KEY", "--plain", "--value", "x"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        vault.stderr(&out).contains("ACME:KEY"),
        "{}",
        vault.stderr(&out)
    );
    let out = vault.run(&["add", "ACME:KEY:WEB", "--plain", "--value", "x"]);
    assert!(out.status.success(), "{}", vault.stderr(&out));
}

#[test]
fn run_injects_env_and_passes_status_through() {
    let vault = Vault::new("run");
    vault.skeleton();
    vault.run(&["add", "T:K:A", "--plain", "--value", "hello"]);
    let out = vault.run(&[
        "run",
        "--use",
        "T:K:A=GREETING",
        "--",
        "sh",
        "-c",
        "echo $GREETING",
    ]);
    assert!(out.status.success());
    assert_eq!(vault.stdout(&out), "hello\n");
    let out = vault.run(&["run", "--use", "T:K:A=GREETING", "--", "sh", "-c", "exit 3"]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn run_missing_secret_spawns_nothing() {
    let vault = Vault::new("run-missing");
    vault.skeleton();
    let sentinel = vault.dir.join("spawned");
    let sentinel_str = sentinel.to_string_lossy().into_owned();
    let out = vault.run(&["run", "--use", "T:K:NOPE=K", "--", "touch", &sentinel_str]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!sentinel.exists());
    let out = vault.run(&["run", "--use", "T:K:A=lower", "--", "true"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn run_reads_the_manifest() {
    let vault = Vault::new("run-manifest");
    vault.skeleton();
    vault.run(&["add", "T:K:A", "--plain", "--value", "from-manifest"]);
    std::fs::write(
        vault.dir.join(".sec.toml"),
        "[use]\nWORD = \"T:K:A\"\nSKIPPED = { address = \"T:K:NOPE\", optional = true }\n",
    )
    .unwrap();
    let out = vault.run(&["run", "--", "sh", "-c", "echo $WORD"]);
    assert!(out.status.success(), "{}", vault.stderr(&out));
    assert_eq!(vault.stdout(&out), "from-manifest\n");
}

#[test]
fn push_dry_run_names_values_never() {
    let vault = Vault::new("push");
    vault.skeleton();
    vault.run(&["add", "T:K:A", "--plain", "--value", "supersecret-value"]);
    let out = vault.run(&[
        "push",
        "--dry-run",
        "--use",
        "T:K:A=REMOTE_KEY",
        "me@vps:/srv/app/.env",
    ]);
    assert!(out.status.success(), "{}", vault.stderr(&out));
    let text = vault.stdout(&out);
    assert!(text.contains("would send 1 values"), "{text}");
    assert!(text.contains("REMOTE_KEY"), "{text}");
    assert!(!text.contains("supersecret-value"), "{text}");
    let value = parse_json(&vault.run(&[
        "push",
        "--dry-run",
        "--use",
        "T:K:A=REMOTE_KEY",
        "--json",
        "me@vps:/srv/app/.env",
    ]));
    assert_eq!(value["ok"], true);
    assert_eq!(value["sent"], 1);
    let out = vault.run(&["push", "--dry-run", "--use", "T:K:A=K"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn push_base_warns_on_shadowed_names() {
    let vault = Vault::new("push-base");
    vault.skeleton();
    vault.run(&["add", "T:K:A", "--plain", "--value", "store-wins"]);
    let base = vault.dir.join("base.env");
    std::fs::write(&base, "REMOTE_KEY=base-value\nOTHER=1\n").unwrap();
    let out = vault.run(&[
        "push",
        "--dry-run",
        "--base",
        &base.to_string_lossy(),
        "--use",
        "T:K:A=REMOTE_KEY",
        "me@vps:/srv/app/.env",
    ]);
    assert!(out.status.success(), "{}", vault.stderr(&out));
    assert!(
        vault
            .stdout(&out)
            .contains("REMOTE_KEY are also in base.env")
    );
}

#[test]
fn check_reports_a_keyless_store() {
    let vault = Vault::new("check");
    vault.skeleton();
    vault.run(&["add", "T:K:A", "--plain", "--value", "x"]);
    let out = vault.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    let text = vault.stdout(&out);
    assert!(text.contains("1 secrets"), "{text}");
    assert!(text.contains("MISSING"), "{text}");
    let value = parse_json(&vault.run(&["check", "--json"]));
    assert_eq!(value["ok"], true);
    assert_eq!(value["key"]["present"], false);
    assert_eq!(value["files"]["plain"], 1);
}

#[test]
fn check_fails_on_broken_schema_and_missing_store() {
    let vault = Vault::new("check-bad");
    vault.skeleton();
    std::fs::write(vault.dir.join("schema.toml"), "[T.P\n").unwrap();
    let out = vault.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(vault.stdout(&out).contains("schema:  ERROR"));
    let bare = Vault::new("check-nostore");
    let out = bare.run(&["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(vault.stdout(&out).contains("MISSING"));
}

#[test]
fn help_usage_and_json_errors() {
    let vault = Vault::new("help");
    let out = vault.run(&["help"]);
    assert!(out.status.success());
    assert!(vault.stdout(&out).contains("est-vault list"));
    let out = vault.run(&["bogus"]);
    assert_eq!(out.status.code(), Some(2));
    let out = vault.run(&[]);
    assert_eq!(out.status.code(), Some(2));
    vault.skeleton();
    let out = vault.run(&["get", "T:K:NOPE", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let value = parse_json(&out);
    assert_eq!(value["ok"], false);
    assert_eq!(value["v"], 1);
    assert!(value["error"].as_str().unwrap().contains("no secret"));
}

/// Fake `scp`/`ssh` on PATH: the scp stub keeps a copy of whatever file
/// it was asked to send (so the ssh stub can hash the *actual* staged
/// bytes with AUTO), both record their argv, and exits/outputs are driven
/// by `EST_STUB_SCP_EXIT` / `EST_STUB_SSH_HEX`. No network exists here.
fn stub_ssh(vault: &Vault) -> PathBuf {
    let bin = vault.dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("scp"),
        "#!/bin/sh\necho \"$@\" >> \"$EST_STUB_DIR/scp-args\"\nfor a in \"$@\"; do\n  if [ -f \"$a\" ]; then cp \"$a\" \"$EST_STUB_DIR/staged.env\"; fi\ndone\nexit ${EST_STUB_SCP_EXIT:-0}\n",
    )
    .unwrap();
    std::fs::write(
        bin.join("ssh"),
        "#!/bin/sh\necho \"$@\" >> \"$EST_STUB_DIR/ssh-args\"\nif [ \"${EST_STUB_SSH_HEX:-AUTO}\" = \"AUTO\" ]; then\n  sum=$(shasum -a 256 \"$EST_STUB_DIR/staged.env\" | cut -d' ' -f1)\n  echo \"$sum  /remote/.env\"\nelse\n  echo \"$EST_STUB_SSH_HEX  /remote/.env\"\nfi\nexit ${EST_STUB_SSH_EXIT:-0}\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for tool in ["scp", "ssh"] {
            let mut perms = std::fs::metadata(bin.join(tool)).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(bin.join(tool), perms).unwrap();
        }
    }
    bin
}

fn push_with_stubs(vault: &Vault, bin: &std::path::Path, args: &[&str]) -> Output {
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    vault
        .cmd(args)
        .env("PATH", path)
        .env("EST_STUB_DIR", vault.dir.clone())
        .output()
        .unwrap()
}

fn push_log(vault: &Vault) -> String {
    std::fs::read_to_string(vault.dir.join("store").join(".push-log")).unwrap_or_default()
}

#[test]
fn push_sends_strict_and_audits() {
    let vault = Vault::new("push-send");
    vault.skeleton();
    vault.run(&["add", "T:K:A", "--plain", "--value", "live-value"]);
    let bin = stub_ssh(&vault);
    let out = push_with_stubs(
        &vault,
        &bin,
        &["push", "--use", "T:K:A=REMOTE_KEY", "me@vps:/srv/app/.env"],
    );
    assert!(out.status.success(), "{}", vault.stderr(&out));
    assert!(
        vault.stdout(&out).contains("sent;"),
        "{}",
        vault.stdout(&out)
    );
    let scp_args = std::fs::read_to_string(vault.dir.join("scp-args")).unwrap_or_default();
    assert!(scp_args.contains("StrictHostKeyChecking=yes"), "{scp_args}");
    assert!(scp_args.contains("BatchMode=yes"), "{scp_args}");
    let staged = std::fs::read_to_string(vault.dir.join("staged.env")).unwrap_or_default();
    assert!(staged.contains("REMOTE_KEY="), "{staged}");
    let log = push_log(&vault);
    assert!(
        log.contains("\tok\tme@vps:/srv/app/.env\t1\tfalse\tREMOTE_KEY"),
        "{log}"
    );
    assert!(!log.contains("live-value"), "{log}");
}

#[test]
fn push_verify_confirms_matching_bytes() {
    let vault = Vault::new("push-verify");
    vault.skeleton();
    vault.run(&["add", "T:K:A", "--plain", "--value", "v1"]);
    let bin = stub_ssh(&vault);
    let out = push_with_stubs(
        &vault,
        &bin,
        &[
            "push",
            "--verify",
            "--use",
            "T:K:A=K",
            "--json",
            "me@vps:/srv/app/.env",
        ],
    );
    assert!(out.status.success(), "{}", vault.stderr(&out));
    let value = parse_json(&out);
    assert_eq!(value["ok"], true);
    assert_eq!(value["verified"], true);
    let ssh_args = std::fs::read_to_string(vault.dir.join("ssh-args")).unwrap_or_default();
    assert!(ssh_args.contains("StrictHostKeyChecking=yes"), "{ssh_args}");
    assert!(ssh_args.contains("BatchMode=yes"), "{ssh_args}");
    assert!(ssh_args.contains("sha256sum"), "{ssh_args}");
    let log = push_log(&vault);
    assert!(
        log.contains("\tok\tme@vps:/srv/app/.env\t1\ttrue\tK"),
        "{log}"
    );
}

#[test]
fn push_verify_refuses_mismatched_bytes() {
    let vault = Vault::new("push-mismatch");
    vault.skeleton();
    vault.run(&["add", "T:K:A", "--plain", "--value", "v1"]);
    let bin = stub_ssh(&vault);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = vault
        .cmd(&[
            "push",
            "--verify",
            "--use",
            "T:K:A=K",
            "me@vps:/srv/app/.env",
        ])
        .env("PATH", path)
        .env("EST_STUB_DIR", vault.dir.clone())
        .env(
            "EST_STUB_SSH_HEX",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        vault.stderr(&out).contains("differ"),
        "{}",
        vault.stderr(&out)
    );
    let log = push_log(&vault);
    assert!(log.contains("\tmismatch\t"), "{log}");
}

#[test]
fn push_scp_failure_is_audited_and_explains_host_keys() {
    let vault = Vault::new("push-scpfail");
    vault.skeleton();
    vault.run(&["add", "T:K:A", "--plain", "--value", "v1"]);
    let bin = stub_ssh(&vault);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = vault
        .cmd(&["push", "--use", "T:K:A=K", "me@vps:/srv/app/.env"])
        .env("PATH", path)
        .env("EST_STUB_DIR", vault.dir.clone())
        .env("EST_STUB_SCP_EXIT", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        vault.stderr(&out).contains("host keys"),
        "{}",
        vault.stderr(&out)
    );
    let log = push_log(&vault);
    assert!(
        log.contains("\tfailed\tme@vps:/srv/app/.env\t0\tfalse\tK"),
        "{log}"
    );
}
