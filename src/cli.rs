//! est-vault: the secrets store from a terminal.
//!
//! Addresses travel through here; values only ride stdin into the store,
//! stdout out of `get`, the envelope into a child, or scp to a server —
//! never a log, and never a screen except through `get`.

use std::io::{Read, Write};
use std::path::Path;

use crate as est_vault;
use crate::store::{Sealed, Store};
use est_core::cli;

/// Help and usage text for est-vault CLI.
pub const USAGE: &str = "\
est-vault: the secrets store.

  est-vault where                      show the store and template paths
  est-vault init                       make a store where `where` points
  est-vault list [PREFIX]              addresses, one per line
  est-vault add ADDR [--plain|--secret] [--file NAME] [--replace] [--value V]
                                       value rides --value or stdin
  est-vault get ADDR [--out PATH]      print the value (files need --out)
  est-vault remove ADDR [--yes]        delete forever (asks unless --yes)
  est-vault stale [--days N]           secret ages; flags older than N days (default 90)
  est-vault rotate ADDR [--yes]        re-seal with a fresh nonce + reset age
                                       (then regenerate at the provider + add --replace)
  est-vault templates                  every added template
  est-vault template add TPL [--plain] [--file] [--hint H] [--about A]
  est-vault template delete PROVIDER KIND   (refuses while in use)
  est-vault run --use ADDR=ENV ... -- CMD ...
                                       run CMD with the secrets as env vars
  est-vault run [--file F] [--use ADDR=ENV]... -- CMD ...
                                       same, plus a .sec.toml manifest
  est-vault push [--file F] [--use ADDR=ENV]... [--base F] [--dry-run] [--verify] HOST:PATH
                                       send a built .env to a server over scp
  est-vault check                      store, key, schema, and files

  --json rides on any command and prints one object instead of text.";

/// Dispatches est-vault CLI arguments.
pub fn dispatch(args: &[String], json: bool) -> i32 {
    let Some(sub) = args.first().map(String::as_str) else {
        eprintln!("{USAGE}");
        return 2;
    };
    match sub {
        "where" => {
            let store = Store::standard();
            if json {
                println!(
                    "{}",
                    cli::ok(&format!(
                        "\"store\":\"{}\",\"templates\":\"{}\",\"keychain\":\"{}\"",
                        cli::esc(&store.dir().display().to_string()),
                        cli::esc(&store.schema_path().display().to_string()),
                        cli::esc(&est_vault::keychain::service()),
                    ))
                );
            } else {
                println!("store:     {}", store.dir().display());
                println!("templates: {}", store.schema_path().display());
                println!("keychain:  {}", est_vault::keychain::service());
            }
            0
        }
        "init" => match Store::standard().init() {
            Ok(()) => {
                let dir = Store::standard().dir().display().to_string();
                if json {
                    println!("{}", cli::ok(&format!("\"store\":\"{}\"", cli::esc(&dir))));
                } else {
                    println!("store ready at {dir}");
                }
                0
            }
            Err(e) => fail(json, &e.to_string()),
        },
        "list" => {
            let prefix = args.get(1).map(String::as_str).unwrap_or("");
            let store = Store::standard();
            let addrs = store.addresses(prefix);
            if json {
                let items: Vec<String> = addrs
                    .iter()
                    .map(|a| {
                        let storage = if store.is_plain(a) {
                            "plain"
                        } else {
                            "encrypted"
                        };
                        format!(
                            "{{\"address\":\"{}\",\"storage\":\"{storage}\"}}",
                            cli::esc(a)
                        )
                    })
                    .collect();
                println!(
                    "{}",
                    cli::ok(&format!("\"addresses\":[{}]", items.join(",")))
                );
            } else {
                for addr in &addrs {
                    println!("{addr}");
                }
            }
            0
        }
        "add" => cmd_add(&args[1..], json),
        "get" => cmd_get(&args[1..], json),
        "remove" => cmd_remove(&args[1..], json),
        "stale" => cmd_stale(&args[1..], json),
        "rotate" => cmd_rotate(&args[1..], json),
        "templates" => cmd_templates(json),
        "template" => match args.get(1).map(String::as_str) {
            Some("add") => cmd_teach(&args[2..], json),
            Some("delete") => cmd_forget(&args[2..], json),
            Some("list") | None => cmd_templates(json),
            Some(other) => {
                eprintln!("est-vault template: unknown {other:?}\n{USAGE}");
                2
            }
        },
        "run" => cmd_run(&args[1..], json),
        "push" => cmd_push(&args[1..], json),
        "check" => cmd_check(json),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            0
        }
        other => {
            eprintln!("est-vault: unknown {other:?}\n{USAGE}");
            2
        }
    }
}

/// A failed command: the envelope on stdout in JSON mode, `est-vault: …`
/// on stderr otherwise. Exit 1; usage errors return 2 directly.
fn fail(json: bool, msg: &str) -> i32 {
    if json {
        println!("{}", cli::err(msg));
    } else {
        cli::print_error("est-vault", msg);
    }
    1
}

/// Deletes ask first: `--yes` skips, a terminal is prompted, and anything
/// else refuses rather than guessing.
fn confirmed(yes: bool, prompt: &str) -> bool {
    use std::io::IsTerminal;
    match cli::confirm_destructive(yes, std::io::stdin().is_terminal()) {
        cli::Confirm::Proceed => true,
        cli::Confirm::Refuse => false,
        cli::Confirm::Ask => {
            eprint!("{prompt}");
            let _ = std::io::stderr().flush();
            let mut answer = String::new();
            if std::io::stdin().read_line(&mut answer).is_err() {
                return false;
            }
            matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
        }
    }
}

fn cmd_add(args: &[String], json: bool) -> i32 {
    let mut addr = "";
    let mut plain: Option<bool> = None;
    let mut file = "";
    let mut replace = false;
    let mut value = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--plain" => plain = Some(true),
            "--secret" => plain = Some(false),
            "--replace" => replace = true,
            "--file" => {
                i += 1;
                file = args.get(i).map(String::as_str).unwrap_or("");
            }
            "--value" => {
                i += 1;
                value = args.get(i).cloned();
            }
            flag if flag.starts_with("--") => {
                eprintln!("est-vault add: unknown {flag:?}");
                return 2;
            }
            a if addr.is_empty() => addr = a,
            extra => {
                eprintln!("est-vault add: unexpected {extra:?}");
                return 2;
            }
        }
        i += 1;
    }
    if addr.is_empty() {
        eprintln!("est-vault add: needs an address");
        return 2;
    }
    let value = match value {
        Some(v) => v,
        None => {
            let mut text = String::new();
            if std::io::stdin().read_to_string(&mut text).is_err() {
                return fail(json, "cannot read the value from stdin");
            }
            let no_nl = text.strip_suffix('\n').unwrap_or(&text);
            no_nl.strip_suffix('\r').unwrap_or(no_nl).to_string()
        }
    };
    if value.is_empty() {
        return fail(json, "there is nothing to store");
    }
    let store = Store::standard();
    let addr = match est_vault::addr::norm(addr) {
        Ok(a) => a,
        Err(e) => return fail(json, &e.to_string()),
    };
    if store.exists(&addr) && !replace {
        return fail(
            json,
            &format!("{addr} is in the store (pass --replace to overwrite it)"),
        );
    }
    if !store.has_store() {
        return fail(
            json,
            &format!(
                "no store at {} (run `est-vault init`)",
                store.dir().display()
            ),
        );
    }
    let note = match est_vault::schema::Schema::load(store.schema_path()) {
        Ok(schema) => match est_vault::schema::check(&schema, &addr) {
            Ok(note) => note,
            Err(e) => return fail(json, &e.to_string()),
        },
        Err(e) => return fail(json, &e.to_string()),
    };
    if !json && let Some(note) = &note {
        eprintln!("{note}");
    }
    let done = if file.trim().is_empty() {
        store.store_text(&addr, &value, plain).map(|_| ())
    } else {
        store.set_file(&addr, file.trim(), value.as_bytes())
    };
    match done {
        Ok(()) => {
            if json {
                let note = note
                    .map(|n| format!(",\"note\":\"{}\"", cli::esc(&n)))
                    .unwrap_or_default();
                println!(
                    "{}",
                    cli::ok(&format!("\"address\":\"{}\"{note}", cli::esc(&addr)))
                );
            } else {
                println!("added {addr}");
            }
            0
        }
        Err(e) => fail(json, &e.to_string()),
    }
}

fn cmd_get(args: &[String], json: bool) -> i32 {
    let mut addr = "";
    let mut out = "";
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out = args.get(i).map(String::as_str).unwrap_or("");
            }
            flag if flag.starts_with("--") => {
                eprintln!("est-vault get: unknown {flag:?}");
                return 2;
            }
            a if addr.is_empty() => addr = a,
            extra => {
                eprintln!("est-vault get: unexpected {extra:?}");
                return 2;
            }
        }
        i += 1;
    }
    if addr.is_empty() {
        eprintln!("est-vault get: needs an address");
        return 2;
    }
    // Raw bytes either way: no envelope belongs around a value.
    match Store::standard().unseal(addr) {
        Ok(Sealed::Text(bytes)) => {
            if out.is_empty() {
                let _ = std::io::stdout().write_all(&bytes);
            } else if let Err(e) = std::fs::write(out, &bytes) {
                return fail(json, &format!("cannot write {out}: {e}"));
            }
            0
        }
        Ok(Sealed::File { name, data }) => {
            if out.is_empty() {
                return fail(json, &format!("{name} is file bytes; pass --out PATH"));
            }
            match std::fs::write(out, &data) {
                Ok(()) => 0,
                Err(e) => fail(json, &format!("cannot write {out}: {e}")),
            }
        }
        Err(e) => fail(json, &e.to_string()),
    }
}

fn cmd_remove(args: &[String], json: bool) -> i32 {
    let mut addr = "";
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--yes" => yes = true,
            flag if flag.starts_with("--") => {
                eprintln!("est-vault remove: unknown {flag:?}");
                return 2;
            }
            a if addr.is_empty() => addr = a,
            extra => {
                eprintln!("est-vault remove: unexpected {extra:?}");
                return 2;
            }
        }
    }
    if addr.is_empty() {
        eprintln!("est-vault remove: needs an address");
        return 2;
    }
    if !confirmed(yes, &format!("delete {addr} forever? [y/N] ")) {
        return fail(json, "not deleted (pass --yes to skip asking)");
    }
    match Store::standard().remove(addr) {
        Ok(()) => {
            let addr = est_vault::addr::norm(addr).unwrap_or_default();
            if json {
                println!(
                    "{}",
                    cli::ok(&format!("\"address\":\"{}\"", cli::esc(&addr)))
                );
            } else {
                println!("deleted {addr}");
            }
            0
        }
        Err(e) => fail(json, &e.to_string()),
    }
}

/// Days since a secret's file was last written (enc twin wins, like
/// reads). `None` when the address holds nothing.
fn secret_age_days(store: &Store, addr: &str) -> Option<u64> {
    use crate::store::{ENC_SUFFIX, PLAIN_SUFFIX};
    let addr = est_vault::addr::norm(addr).ok()?;
    let path = {
        let enc = store.path_of(&addr, ENC_SUFFIX);
        if enc.is_file() {
            enc
        } else {
            let plain = store.path_of(&addr, PLAIN_SUFFIX);
            if plain.is_file() {
                plain
            } else {
                return None;
            }
        }
    };
    let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let age = std::time::SystemTime::now()
        .duration_since(mtime)
        .unwrap_or_default()
        .as_secs()
        / 86_400;
    Some(age)
}

/// List secret ages; flag rows older than `--days` (default 90).
/// Age is the file mtime: any write (`add --replace`, `rotate`)
/// resets it. Read-only: values never leave the store.
fn cmd_stale(args: &[String], json: bool) -> i32 {
    let mut days = 90u64;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--days" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u64>().ok()) {
                    Some(n) => days = n,
                    None => {
                        eprintln!("est-vault stale: --days needs a number");
                        return 2;
                    }
                }
            }
            flag => {
                eprintln!("est-vault stale: unexpected {flag:?}");
                return 2;
            }
        }
        i += 1;
    }
    let store = Store::standard();
    let mut rows = Vec::new();
    for addr in store.addresses("") {
        let age = secret_age_days(&store, &addr).unwrap_or(0);
        let storage = if store.is_plain(&addr) {
            "plain"
        } else {
            "encrypted"
        };
        rows.push((addr, age, storage, age > days));
    }
    if json {
        let items: Vec<String> = rows
            .iter()
            .map(|(a, age, storage, stale)| {
                format!(
                    "{{\"address\":\"{}\",\"age_days\":{age},\"storage\":\"{storage}\",\"stale\":{stale}}}",
                    cli::esc(a)
                )
            })
            .collect();
        println!(
            "{}",
            cli::ok(&format!(
                "\"threshold_days\":{days},\"secrets\":[{}]",
                items.join(",")
            ))
        );
    } else if rows.is_empty() {
        println!("no secrets stored");
    } else {
        println!("{:<34} {:<5} {:<9} STATE", "ADDRESS", "AGE", "STORAGE");
        for (addr, age, storage, stale) in &rows {
            println!(
                "{addr:<34} {age:<5} {storage:<9} {}",
                if *stale { "STALE" } else { "ok" }
            );
        }
    }
    0
}

/// Re-seal one secret under a fresh nonce and reset its age. This
/// refreshes the encryption, not the credential: the checklist after
/// is regenerate at the provider, then `add --replace`.
fn cmd_rotate(args: &[String], json: bool) -> i32 {
    let mut addr = "";
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--yes" => yes = true,
            flag if flag.starts_with("--") => {
                eprintln!("est-vault rotate: unknown {flag:?}");
                return 2;
            }
            a if addr.is_empty() => addr = a,
            extra => {
                eprintln!("est-vault rotate: unexpected {extra:?}");
                return 2;
            }
        }
    }
    if addr.is_empty() {
        eprintln!("est-vault rotate: needs an address");
        return 2;
    }
    if !confirmed(yes, &format!("re-seal {addr} with a fresh nonce? [y/N] ")) {
        return fail(json, "not rotated (pass --yes to skip asking)");
    }
    let store = Store::standard();
    let opened = match store.unseal(addr) {
        Ok(s) => s,
        Err(e) => return fail(json, &e.to_string()),
    };
    let outcome = match opened {
        Sealed::Text(bytes) => store.seal(addr, &bytes),
        Sealed::File { name, data } => store.set_file(addr, &name, &data),
    };
    if let Err(e) = outcome {
        return fail(json, &e.to_string());
    }
    let addr = est_vault::addr::norm(addr).unwrap_or_default();
    if json {
        println!(
            "{}",
            cli::ok(&format!("\"address\":\"{}\"", cli::esc(&addr)))
        );
    } else {
        println!("rotated {addr} (fresh nonce, age reset)");
        println!("next: regenerate at the provider, then `est-vault add {addr} --replace`");
    }
    0
}

fn cmd_templates(json: bool) -> i32 {
    let store = Store::standard();
    let schema = match est_vault::schema::Schema::load(store.schema_path()) {
        Ok(s) => s,
        Err(e) => return fail(json, &e.to_string()),
    };
    if json {
        let mut items = Vec::new();
        for provider in &schema.providers {
            for kind in &provider.kinds {
                let scope: Vec<String> = kind
                    .scope
                    .iter()
                    .map(|s| format!("\"{}\"", cli::esc(s)))
                    .collect();
                let hint = kind
                    .hint
                    .as_deref()
                    .map(|h| format!(",\"hint\":\"{}\"", cli::esc(h)))
                    .unwrap_or_default();
                items.push(format!(
                    "{{\"template\":\"{}\",\"provider\":\"{}\",\"kind\":\"{}\",\"scope\":[{}],\"plain\":{},\"file\":{}{hint}}}",
                    cli::esc(&est_vault::schema::template(
                        &provider.name,
                        &kind.name,
                        &kind.scope
                    )),
                    cli::esc(&provider.name),
                    cli::esc(&kind.name),
                    scope.join(","),
                    kind.plain,
                    kind.file,
                ));
            }
        }
        println!(
            "{}",
            cli::ok(&format!("\"templates\":[{}]", items.join(",")))
        );
        return 0;
    }
    for provider in &schema.providers {
        for kind in &provider.kinds {
            let mut flags = String::new();
            if kind.plain {
                flags.push_str(" plain");
            }
            if kind.file {
                flags.push_str(" file");
            }
            println!(
                "{}{}",
                est_vault::schema::template(&provider.name, &kind.name, &kind.scope),
                flags
            );
        }
    }
    0
}

fn cmd_teach(args: &[String], json: bool) -> i32 {
    let mut template = "";
    let mut plain = false;
    let mut file = false;
    let mut hint = "";
    let mut about = "";
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--plain" => plain = true,
            "--file" => file = true,
            "--hint" => {
                i += 1;
                hint = args.get(i).map(String::as_str).unwrap_or("");
            }
            "--about" => {
                i += 1;
                about = args.get(i).map(String::as_str).unwrap_or("");
            }
            flag if flag.starts_with("--") => {
                eprintln!("est-vault template add: unknown {flag:?}");
                return 2;
            }
            t if template.is_empty() => template = t,
            extra => {
                eprintln!("est-vault template add: unexpected {extra:?}");
                return 2;
            }
        }
        i += 1;
    }
    if template.is_empty() {
        eprintln!("est-vault template add: needs PROVIDER:KIND:<VAR>...");
        return 2;
    }
    let hint = (!hint.trim().is_empty()).then(|| hint.trim());
    let about = (!about.trim().is_empty()).then(|| about.trim());
    let store = Store::standard();
    match est_vault::schema::define(
        store.schema_path(),
        template.trim(),
        plain,
        file,
        hint,
        about,
    ) {
        Ok((_, added)) => {
            if json {
                println!(
                    "{}",
                    cli::ok(&format!("\"template\":\"{}\"", cli::esc(&added)))
                );
            } else {
                println!("added template {added}");
            }
            0
        }
        Err(e) => fail(json, &e.to_string()),
    }
}

fn cmd_forget(args: &[String], json: bool) -> i32 {
    if args.len() != 2 {
        eprintln!("est-vault template delete: needs PROVIDER KIND");
        return 2;
    }
    let (provider, kind) = (args[0].as_str(), args[1].as_str());
    let store = Store::standard();
    let users = store.addresses(&format!("{provider}:{kind}:"));
    if !users.is_empty() {
        return fail(
            json,
            &format!(
                "{} address(es) still use [{provider}.{kind}]; delete them first",
                users.len()
            ),
        );
    }
    match est_vault::schema::undefine(store.schema_path(), provider, kind) {
        Ok(()) => {
            if json {
                println!(
                    "{}",
                    cli::ok(&format!(
                        "\"provider\":\"{}\",\"kind\":\"{}\"",
                        cli::esc(provider),
                        cli::esc(kind)
                    ))
                );
            } else {
                println!("deleted template {provider}.{kind}");
            }
            0
        }
        Err(e) => fail(json, &e.to_string()),
    }
}

/// The envelope children run under: every `--use ADDR=ENV` opens before
/// the child spawns, so a missing secret fails the run instead of running
/// naked. File secrets land in a private temp dir the env var points at;
/// the dir is removed when the child exits. Exits with the child's status.
fn cmd_run(args: &[String], json: bool) -> i32 {
    let mut uses: Vec<(String, String)> = Vec::new();
    let mut manifest: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--use" => {
                i += 1;
                let pair = args.get(i).map(String::as_str).unwrap_or("");
                let Some((addr, env)) = pair.split_once('=') else {
                    eprintln!("est-vault run: --use needs ADDR=ENV, got {pair:?}");
                    return 2;
                };
                if !valid_env(env.trim()) {
                    eprintln!("est-vault run: bad env {env:?}: want UPPER_SNAKE");
                    return 2;
                }
                uses.push((addr.trim().to_string(), env.trim().to_string()));
            }
            "--file" => {
                i += 1;
                let path = args.get(i).map(String::as_str).unwrap_or("").trim();
                if path.is_empty() {
                    eprintln!("est-vault run: --file needs a path");
                    return 2;
                }
                manifest = Some(path.to_string());
            }
            "--" => {
                i += 1;
                break;
            }
            flag => {
                eprintln!(
                    "est-vault run: unexpected {flag:?} (want [--file F] --use ADDR=ENV ... -- CMD ...)"
                );
                return 2;
            }
        }
        i += 1;
    }
    let store = Store::standard();
    match manifest_uses(manifest.as_deref(), &store) {
        Ok(mut from_file) => {
            from_file.append(&mut uses);
            uses = from_file;
        }
        Err(e) => return fail(json, &e),
    }
    if uses.is_empty() {
        eprintln!("est-vault run: name at least one --use ADDR=ENV (or keep a .sec.toml here)");
        return 2;
    }
    let cmd: Vec<&str> = args[i..].iter().map(String::as_str).collect();
    if cmd.is_empty() {
        eprintln!("est-vault run: needs a command after --");
        return 2;
    }
    let mut child = std::process::Command::new(cmd[0]);
    child.args(&cmd[1..]);
    let mut files_dir = None;
    for (addr, env) in &uses {
        match store.unseal(addr) {
            Ok(Sealed::Text(bytes)) => {
                use std::os::unix::ffi::OsStrExt;
                child.env(env, std::ffi::OsStr::from_bytes(&bytes));
            }
            Ok(Sealed::File { name, data }) => {
                let dir: &std::path::PathBuf = files_dir.get_or_insert_with(|| {
                    let dir =
                        std::env::temp_dir().join(format!("est-vault-run-{}", std::process::id()));
                    let _ = est_core::store::create_dir_all_mode(&dir, 0o700);
                    dir
                });
                let path = dir.join(sanitize_file(&name));
                use std::os::unix::fs::OpenOptionsExt;
                let written = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&path)
                    .and_then(|mut f| f.write_all(&data).map(|_| f))
                    .and_then(|f| f.sync_all());
                if written.is_err() {
                    eprintln!("est-vault run: cannot stage {addr}");
                    cleanup(&files_dir);
                    return 1;
                }
                child.env(env, &path);
            }
            Err(e) => {
                eprintln!("est-vault run: {e}");
                cleanup(&files_dir);
                return 1;
            }
        }
    }
    let status = child.status();
    cleanup(&files_dir);
    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("est-vault run: cannot spawn {}: {e}", cmd[0]);
            1
        }
    }
}

fn sanitize_file(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.is_empty() {
        "secret".to_string()
    } else {
        clean
    }
}

fn cleanup(dir: &Option<std::path::PathBuf>) {
    if let Some(dir) = dir {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Env names are UPPER_SNAKE: leading uppercase or underscore, then
/// uppercase, digits, underscores.
fn valid_env(env: &str) -> bool {
    let mut chars = env.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// (addr, env) pairs from a `.sec.toml` manifest: explicit `--file`, else
/// the one found walking up from the working directory (stopping at $HOME),
/// else nothing — a missing manifest is fine when `--use` names secrets.
/// `optional = true` entries skip silently when unstored; anything else
/// missing fails here, before a child spawns or an scp runs.
fn manifest_uses(explicit: Option<&str>, store: &Store) -> Result<Vec<(String, String)>, String> {
    let path = match explicit {
        Some(p) => {
            if !Path::new(p).is_file() {
                return Err(format!("no manifest at {p}"));
            }
            Some(Path::new(p).to_path_buf())
        }
        None => find_manifest(),
    };
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut uses = Vec::new();
    for (env, addr, optional) in parse_manifest(&text).map_err(|line| {
        format!("{} line {line}: want ENV = \"ADDR\" or ENV = {{ address = \"ADDR\", optional = true }}", path.display())
    })? {
        if !valid_env(&env) {
            return Err(format!("{}: bad env {env:?}: want UPPER_SNAKE", path.display()));
        }
        if optional && !store.exists(&addr) {
            continue;
        }
        uses.push((addr, env));
    }
    Ok(uses)
}

fn find_manifest() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let cand = dir.join(".sec.toml");
        if cand.is_file() {
            return Some(cand);
        }
        if dir.to_string_lossy() == home {
            return None;
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// The narrow TOML `run` and `push` need: the `[use]` table only, one
/// entry per line, `#` comments outside strings. Errors name the line
/// number, never the line — manifests hold addresses, but caution is free.
fn parse_manifest(text: &str) -> Result<Vec<(String, String, bool)>, usize> {
    let mut out = Vec::new();
    let mut in_use = false;
    for (n, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_use = line == "[use]";
            continue;
        }
        if !in_use {
            continue;
        }
        let (env, spec) = raw.split_once('=').ok_or(n + 1).and_then(|(k, v)| {
            let k = strip_comment(k).trim();
            if k.is_empty() {
                Err(n + 1)
            } else {
                Ok((k.to_string(), v))
            }
        })?;
        let spec = strip_comment(spec).trim();
        if let Some(inner) = spec.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            let addr = inline_field(inner, "address").ok_or(n + 1)?;
            let optional = inline_field(inner, "optional").is_some_and(|v| v == "true");
            out.push((env, addr, optional));
        } else {
            out.push((env, toml_string(spec).ok_or(n + 1)?, false));
        }
    }
    Ok(out)
}

fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut esc = false;
    for (i, c) in line.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' if in_str => esc = true,
            '"' => in_str = !in_str,
            '#' if !in_str => return line[..i].trim_end(),
            _ => {}
        }
    }
    line
}

fn toml_string(spec: &str) -> Option<String> {
    let body = spec.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                c => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn inline_field(inner: &str, key: &str) -> Option<String> {
    for part in inner.split(',') {
        let (k, v) = part.split_once('=')?;
        if k.trim() == key {
            let v = v.trim();
            if v == "true" || v == "false" {
                return Some(v.to_string());
            }
            return toml_string(v);
        }
    }
    None
}

/// One `KEY=value` line a compose or docker env-file reads back exactly.
/// Values with line breaks, or a `'` mixed with other specials, refuse:
/// a .env that parses back differently is a credential bug.
fn dotenv_line(name: &str, value: &str) -> Result<String, String> {
    if value.contains('\n') || value.contains('\r') {
        return Err(format!(
            "{name}: a value with a line break cannot be written to a .env file"
        ));
    }
    let safe = !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '~' | '-'
                )
        });
    if safe {
        return Ok(format!("{name}={value}"));
    }
    if value.contains('\'') {
        return Err(format!(
            "{name}: a value with a ' and other special characters cannot be written safely to a .env file"
        ));
    }
    Ok(format!("{name}='{value}'"))
}

/// Single-quote a remote path for sh: `o'clock` → `'o'\''clock'`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The SHA-256 of bytes, lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Ask the server what it received: `sha256sum`, falling back to macOS
/// `shasum`. Returns the remote digest, or why it could not be read.
fn verify_remote(host: &str, remote: &str) -> Result<String, String> {
    let quoted = sh_quote(remote);
    let probe = format!("sha256sum {quoted} 2>/dev/null || shasum -a 256 {quoted}");
    let out = std::process::Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "BatchMode=yes",
            host,
            &probe,
        ])
        .output()
        .map_err(|e| format!("could not run ssh: {e}"))?;
    if !out.status.success() {
        return Err(format!("ssh exited {}", out.status.code().unwrap_or(1)));
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or_else(|| "no digest in the ssh output".to_string())
}

/// Append one TSV line to `<store>/.push-log` (0600): when, result,
/// target, count, verified, env names. Never values. Best-effort: a log
/// failure warns but never fails the push it records.
fn audit_push(
    store: &Store,
    result: &str,
    target: &str,
    sent: usize,
    verified: bool,
    names: &[String],
) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!(
        "{secs}\t{result}\t{target}\t{sent}\t{verified}\t{}\n",
        names.join(",")
    );
    let wrote = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(store.dir().join(".push-log"))
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(line.as_bytes())
            })
            .is_ok()
    };
    if !wrote {
        eprintln!("note: the push was attempted but the audit log refused the line");
    }
}

/// Build a `.env` from the store and scp it to a server: the deploy path.
/// `--base` prepends a local file (store values come last and win);
/// `--dry-run` names what would go, nothing made or sent; `--verify`
/// re-reads the remote file over ssh and compares digests before
/// reporting success. Files refuse — a .env holds values; a file secret
/// travels to the server separately. Every send (and every failed send)
/// appends to `<store>/.push-log`, names only, never values.
fn cmd_push(args: &[String], json: bool) -> i32 {
    let mut uses: Vec<(String, String)> = Vec::new();
    let mut manifest: Option<String> = None;
    let mut base: Option<String> = None;
    let mut dry_run = false;
    let mut verify = false;
    let mut target = "";
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--use" => {
                i += 1;
                let pair = args.get(i).map(String::as_str).unwrap_or("");
                let Some((addr, env)) = pair.split_once('=') else {
                    eprintln!("est-vault push: --use needs ADDR=ENV, got {pair:?}");
                    return 2;
                };
                if !valid_env(env.trim()) {
                    eprintln!("est-vault push: bad env {env:?}: want UPPER_SNAKE");
                    return 2;
                }
                uses.push((addr.trim().to_string(), env.trim().to_string()));
            }
            "--file" => {
                i += 1;
                let path = args.get(i).map(String::as_str).unwrap_or("").trim();
                if path.is_empty() {
                    eprintln!("est-vault push: --file needs a path");
                    return 2;
                }
                manifest = Some(path.to_string());
            }
            "--base" => {
                i += 1;
                let path = args.get(i).map(String::as_str).unwrap_or("").trim();
                if path.is_empty() {
                    eprintln!("est-vault push: --base needs a path");
                    return 2;
                }
                base = Some(path.to_string());
            }
            "--dry-run" => dry_run = true,
            "--verify" => verify = true,
            flag if flag.starts_with("--") => {
                eprintln!("est-vault push: unexpected {flag:?}");
                return 2;
            }
            t => {
                if !target.is_empty() {
                    eprintln!("est-vault push: one target, got {t:?} too");
                    return 2;
                }
                target = t;
            }
        }
        i += 1;
    }
    let (host, remote) = target.split_once(':').unwrap_or(("", ""));
    if host.trim().is_empty() || remote.trim().is_empty() {
        eprintln!("est-vault push: the target is HOST:PATH, e.g. me@vps:/srv/backend/.env");
        return 2;
    }
    let store = Store::standard();
    match manifest_uses(manifest.as_deref(), &store) {
        Ok(mut from_file) => {
            from_file.append(&mut uses);
            uses = from_file;
        }
        Err(e) => return fail(json, &e),
    }
    if uses.is_empty() {
        eprintln!("est-vault push: nothing asked for (a .sec.toml here, --file, or --use)");
        return 2;
    }
    let mut lines = Vec::new();
    let mut names = Vec::new();
    for (addr, env) in &uses {
        match store.unseal(addr) {
            Ok(Sealed::Text(bytes)) => {
                let value = String::from_utf8_lossy(&bytes);
                match dotenv_line(env, value.trim_end_matches('\n')) {
                    Ok(line) => {
                        lines.push(line);
                        names.push(env.clone());
                    }
                    Err(e) => return fail(json, &e),
                }
            }
            Ok(Sealed::File { name, .. }) => {
                return fail(
                    json,
                    &format!("{addr} is a file ({name}); a .env holds only values"),
                );
            }
            Err(e) => return fail(json, &format!("{e}")),
        }
    }
    let mut body = String::new();
    if let Some(base_path) = base.as_deref() {
        let base_text = match std::fs::read_to_string(base_path) {
            Ok(t) => t,
            Err(_) => return fail(json, &format!("no base file at {base_path}")),
        };
        let shadowed: Vec<&str> = uses
            .iter()
            .map(|(_, env)| env.as_str())
            .filter(|env| {
                base_text.lines().any(|l| {
                    let l = l.trim_start();
                    l.strip_prefix(env)
                        .is_some_and(|rest| rest.trim_start().starts_with('='))
                })
            })
            .collect();
        if !shadowed.is_empty() && !json {
            let base_name = Path::new(base_path)
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default();
            println!(
                "note: {} are also in {base_name}; the value from the store comes last and wins",
                shadowed.join(", ")
            );
        }
        if !base_text.trim().is_empty() {
            body.push_str(base_text.trim_end_matches('\n'));
            body.push('\n');
        }
    }
    body.push_str("# from est-vault\n");
    body.push_str(&lines.join("\n"));
    body.push('\n');
    if dry_run {
        if json {
            println!(
                "{}",
                cli::ok(&format!(
                    "\"dry_run\":true,\"target\":\"{}\",\"sent\":{}",
                    cli::esc(target),
                    names.len()
                ))
            );
        } else {
            println!(
                "would send {} values to {target}: {}",
                names.len(),
                names.join(", ")
            );
            println!("dry run: nothing was made or sent");
        }
        return 0;
    }
    if !json {
        println!("sending {} values to {target}", names.len());
    }
    let dir = std::env::temp_dir().join(format!("est-vault-push-{}", std::process::id()));
    {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new().mode(0o700).create(&dir);
    }
    let file = dir.join(".env");
    let staged = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(body.as_bytes())
            })
    };
    if staged.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return fail(json, "cannot stage the .env");
    }
    let status = std::process::Command::new("scp")
        .args([
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "BatchMode=yes",
            "-q",
            &file.display().to_string(),
            target,
        ])
        .status();
    let _ = std::fs::remove_dir_all(&dir);
    match status {
        Ok(s) if !s.success() => {
            audit_push(&store, "failed", target, 0, false, &names);
            fail(
                json,
                &format!(
                    "scp failed (exit {}); nothing was left behind — check `ssh {}` connects (unknown host keys refuse: connect once manually to accept)",
                    s.code().unwrap_or(1),
                    host.trim(),
                ),
            )
        }
        Err(e) => {
            audit_push(&store, "failed", target, 0, false, &names);
            fail(json, &format!("could not run scp: {e}"))
        }
        Ok(_) => {
            if verify {
                let digest = sha256_hex(body.as_bytes());
                match verify_remote(host.trim(), remote.trim()) {
                    Ok(got) if got.eq_ignore_ascii_case(&digest) => {
                        audit_push(&store, "ok", target, names.len(), true, &names);
                        if json {
                            println!(
                                "{}",
                                cli::ok(&format!(
                                    "\"target\":\"{}\",\"sent\":{},\"verified\":true",
                                    cli::esc(target),
                                    names.len()
                                ))
                            );
                        } else {
                            println!("sent and verified; the local copy is deleted");
                        }
                        0
                    }
                    Ok(_) => {
                        audit_push(&store, "mismatch", target, names.len(), true, &names);
                        fail(
                            json,
                            &format!(
                                "sent, but the remote bytes differ from what was staged — investigate on {} before deploying",
                                host.trim()
                            ),
                        )
                    }
                    Err(e) => {
                        audit_push(&store, "unverified", target, names.len(), false, &names);
                        fail(
                            json,
                            &format!(
                                "sent, but verification failed ({e}); the remote file is unconfirmed"
                            ),
                        )
                    }
                }
            } else {
                audit_push(&store, "ok", target, names.len(), false, &names);
                if json {
                    println!(
                        "{}",
                        cli::ok(&format!(
                            "\"target\":\"{}\",\"sent\":{}",
                            cli::esc(target),
                            names.len()
                        ))
                    );
                } else {
                    println!("sent; the local copy is deleted");
                }
                0
            }
        }
    }
}

/// Store health: the store exists, the key opens, the schema parses, and
/// every encrypted file opens with the key. Values are opened but never
/// printed; only addresses name failures. Exit 0 only when all four hold.
fn cmd_check(json: bool) -> i32 {
    let store = Store::standard();
    let store_ok = store.has_store();
    let addresses = if store_ok {
        store.addresses("")
    } else {
        Vec::new()
    };
    let (providers, schema_err) = match est_vault::schema::Schema::load(store.schema_path()) {
        Ok(schema) => (schema.providers.len(), None),
        Err(e) => (0, Some(e.to_string())),
    };
    let (key_present, key_err, key) = match est_vault::keychain::get() {
        Ok(Some(key)) => (true, None, Some(key)),
        Ok(None) => (false, None, None),
        Err(e) => (false, Some(e.to_string()), None),
    };
    let mut encrypted = 0;
    let mut plain = 0;
    let mut bad = Vec::new();
    for addr in &addresses {
        if store.is_plain(addr) {
            plain += 1;
            continue;
        }
        encrypted += 1;
        if let Some(key) = &key
            && let Err(e) = store.unseal_with(addr, key)
        {
            bad.push(format!("{addr}: {e}"));
        }
    }
    let failed = !store_ok || schema_err.is_some() || !key_present || !bad.is_empty();
    if json {
        let schema_json = match &schema_err {
            Some(e) => format!("\"error\":\"{}\"", cli::esc(e)),
            None => format!("\"providers\":{providers}"),
        };
        let key_json = match &key_err {
            Some(e) => format!(
                "\"service\":\"{}\",\"present\":false,\"error\":\"{}\"",
                cli::esc(&est_vault::keychain::service()),
                cli::esc(e)
            ),
            None => format!(
                "\"service\":\"{}\",\"present\":{key_present}",
                cli::esc(&est_vault::keychain::service()),
            ),
        };
        let failed_json: Vec<String> = bad.iter().map(|b| format!("\"{}\"", cli::esc(b))).collect();
        println!(
            "{}",
            cli::ok(&format!(
                "\"store\":{{\"path\":\"{}\",\"present\":{store_ok},\"secrets\":{}}},\"key\":{{{key_json}}},\"schema\":{{\"path\":\"{}\",{schema_json}}},\"files\":{{\"encrypted\":{encrypted},\"plain\":{plain},\"failed\":[{}]}}",
                cli::esc(&store.dir().display().to_string()),
                addresses.len(),
                cli::esc(&store.schema_path().display().to_string()),
                failed_json.join(","),
            ))
        );
    } else {
        if store_ok {
            println!(
                "store:   {} ({} secrets)",
                store.dir().display(),
                addresses.len()
            );
        } else {
            println!("store:   {} MISSING", store.dir().display());
        }
        match (&key_present, &key_err) {
            (_, Some(e)) => println!("key:     ERROR {e}"),
            (true, None) => println!("key:     {} (present)", est_vault::keychain::service()),
            (false, None) => println!("key:     {} MISSING", est_vault::keychain::service()),
        }
        match &schema_err {
            Some(e) => println!("schema:  ERROR {e}"),
            None if providers == 0 => {
                println!("schema:  {} (empty)", store.schema_path().display())
            }
            None => println!(
                "schema:  {} ({providers} providers)",
                store.schema_path().display()
            ),
        }
        if store_ok {
            if key_present {
                println!("files:   {encrypted} encrypted open, {plain} plain");
            } else {
                println!("files:   {encrypted} encrypted UNVERIFIED (no key), {plain} plain");
            }
            for line in &bad {
                println!("  FAIL {line}");
            }
        }
    }
    if failed { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_names_are_upper_snake() {
        assert!(valid_env("MASTER_KEY"));
        assert!(valid_env("_X"));
        assert!(valid_env("A1"));
        assert!(!valid_env("lower"));
        assert!(!valid_env("1ABC"));
        assert!(!valid_env("HAS-DASH"));
        assert!(!valid_env(""));
    }

    #[test]
    fn manifest_simple_and_inline_forms() {
        let parsed = parse_manifest(
            "# comment\n[use]\nA = \"X:Y\"\nB = { address = \"P:Q\", optional = true }\n[other]\nC = \"zzz\"\n",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                ("A".to_string(), "X:Y".to_string(), false),
                ("B".to_string(), "P:Q".to_string(), true),
            ]
        );
    }

    #[test]
    fn manifest_errors_name_the_line() {
        assert_eq!(parse_manifest("[use]\nNOPE\n").unwrap_err(), 2);
        assert_eq!(parse_manifest("[use]\nA = nope\n").unwrap_err(), 2);
        assert_eq!(
            parse_manifest("[use]\nA = { optional = true }\n").unwrap_err(),
            2
        );
    }

    #[test]
    fn dotenv_safe_quoted_and_refused() {
        assert_eq!(dotenv_line("A", "abc123").unwrap(), "A=abc123");
        assert_eq!(dotenv_line("A", "a b").unwrap(), "A='a b'");
        assert_eq!(dotenv_line("A", "").unwrap(), "A=''");
        assert!(dotenv_line("A", "x\ny").is_err());
        assert!(dotenv_line("A", "it's $pecial").is_err());
    }

    #[test]
    fn sanitize_keeps_filenames_tame() {
        assert_eq!(sanitize_file("AuthKey.p8"), "AuthKey.p8");
        assert_eq!(sanitize_file("a/b\\c"), "a_b_c");
        assert_eq!(sanitize_file(""), "secret");
    }

    #[test]
    fn quoting_survives_spaces_and_single_quotes() {
        assert_eq!(sh_quote("/srv/app/.env"), "'/srv/app/.env'");
        assert_eq!(sh_quote("o'clock"), "'o'\\''clock'");
        assert_eq!(sh_quote("a b"), "'a b'");
    }

    #[test]
    fn digest_matches_the_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex(b"").len(), 64);
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;
    use crate::store::ENC_SUFFIX;

    fn scratch(name: &str) -> (std::path::PathBuf, Store) {
        let dir =
            std::env::temp_dir().join(format!("est-rotate-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (
            dir.clone(),
            Store::at(dir.join("store"), dir.join("schema.toml")),
        )
    }

    #[test]
    fn fresh_secrets_read_zero_days_and_flag_past_zero() {
        let (_dir, store) = scratch("age");
        let key = [7u8; 32];
        store.seal_with("A:B:C", b"v", &key).unwrap();
        assert_eq!(secret_age_days(&store, "A:B:C"), Some(0));
        assert_eq!(secret_age_days(&store, "NOPE:Q:Z"), None);
        // Threshold 0 flags anything older than brand-new... fresh reads
        // not-stale at any threshold >= 0.
        assert!(secret_age_days(&store, "A:B:C").unwrap() <= 90);
    }

    #[test]
    fn reseal_changes_bytes_and_keeps_value() {
        let (_dir, store) = scratch("reseal");
        let key = [9u8; 32];
        // Text rows carry a 1-byte frame (see `text_roundtrip`).
        let mut framed = vec![b'T'];
        framed.extend_from_slice(b"secret!");
        store.seal_with("A:B:C", &framed, &key).unwrap();
        let before = std::fs::read(store.path_of("A:B:C", ENC_SUFFIX)).unwrap();
        let opened = store.unseal_with("A:B:C", &key).unwrap();
        match opened {
            Sealed::Text(bytes) => {
                let mut reframed = vec![b'T'];
                reframed.extend_from_slice(&bytes);
                store.seal_with("A:B:C", &reframed, &key).unwrap();
            }
            Sealed::File { .. } => panic!("text sealed as file"),
        }
        let after = std::fs::read(store.path_of("A:B:C", ENC_SUFFIX)).unwrap();
        // Fresh nonce: bytes differ, value identical.
        assert_ne!(before, after);
        match store.unseal_with("A:B:C", &key).unwrap() {
            Sealed::Text(bytes) => assert_eq!(bytes, b"secret!"),
            Sealed::File { .. } => panic!("text sealed as file"),
        }
    }
}
