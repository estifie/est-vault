//! The schema: what each provider keeps. [`define`] and [`undefine`] are
//! the only writers; both keep the rest of the file byte for byte.

use std::path::Path;

use crate::Error;

/// The parsed template file. Missing files load as empty, never as errors.
#[derive(Debug)]
pub struct Schema {
    /// When true, unknown providers refuse instead of noting.
    pub strict: bool,
    /// Every provider table, in file order.
    pub providers: Vec<Provider>,
}

/// One `[PROVIDER]` table with its kinds.
#[derive(Debug)]
pub struct Provider {
    /// The provider name, e.g. `GITHUB`.
    pub name: String,
    /// The optional `about` line.
    pub about: Option<String>,
    /// Every `[PROVIDER.KIND]` table, in file order.
    pub kinds: Vec<Kind>,
}

/// One `[PROVIDER.KIND]` table: how its addresses look and store.
#[derive(Debug)]
pub struct Kind {
    /// The kind name, e.g. `PAT`.
    pub name: String,
    /// Scope placeholder names; the address carries one value per name.
    pub scope: Vec<String>,
    /// True when values store unencrypted (`.plain`).
    pub plain: bool,
    /// True when values are file bytes with a name.
    pub file: bool,
    /// The optional `hint` line shown when adding.
    pub hint: Option<String>,
}

impl Schema {
    /// A missing file is an empty schema, not an error.
    pub fn load(path: &Path) -> Result<Schema, Error> {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Ok(Schema {
                strict: false,
                providers: Vec::new(),
            });
        };
        parse(&text).map_err(|(line, msg)| {
            Error::Schema(format!("{}:{line}: not valid TOML: {msg}", path.display()))
        })
    }

    /// The named provider, if the schema describes it.
    pub fn provider(&self, name: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.name == name)
    }

    /// The rule for an address's provider and kind, if both are described.
    pub fn kind_rule(&self, addr: &str) -> Option<&Kind> {
        let mut parts = addr.split(':');
        let provider = self.provider(parts.next()?)?;
        provider
            .kinds
            .iter()
            .find(|k| Some(k.name.as_str()) == parts.next())
    }
}

/// Check an address against the schema: unknown providers note (strict:
/// refuse), unknown kinds and wrong scope counts refuse. `Ok(Some(note))`
/// is the note the CLI prints once; fuzzy suggestions are the CLI's
/// business.
pub fn check(schema: &Schema, addr: &str) -> Result<Option<String>, Error> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() < 2 {
        return Err(Error::Schema(format!("{addr:?} needs PROVIDER:KIND...")));
    }
    let Some(provider) = schema.provider(parts[0]) else {
        if schema.strict {
            return Err(Error::Schema(format!(
                "provider {} is not in the schema (strict mode)",
                parts[0]
            )));
        }
        return Ok(Some(format!(
            "note: {} is not described in the schema yet",
            parts[0]
        )));
    };
    if provider.kinds.is_empty() {
        return Ok(None);
    }
    let Some(kind) = provider.kinds.iter().find(|k| k.name == parts[1]) else {
        let kinds = provider
            .kinds
            .iter()
            .map(|k| k.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(Error::Schema(format!(
            "{} kind must be one of {}; got {}",
            parts[0], kinds, parts[1]
        )));
    };
    if parts.len() != 2 + kind.scope.len() {
        return Err(Error::Schema(format!(
            "{}:{} addresses look like {}; got {addr}",
            parts[0],
            parts[1],
            template(parts[0], parts[1], &kind.scope)
        )));
    }
    Ok(None)
}

/// The address shape users fill in: `PROVIDER:KIND:<VAR>...`.
pub fn template(provider: &str, kind: &str, names: &[String]) -> String {
    format!(
        "{provider}:{kind}:{}",
        names
            .iter()
            .map(|n| format!("<{n}>"))
            .collect::<Vec<_>>()
            .join(":")
    )
}

fn parse(text: &str) -> Result<Schema, (usize, String)> {
    let mut strict = false;
    let mut providers: Vec<Provider> = Vec::new();
    let mut section: Vec<String> = Vec::new();
    for (no, raw) in text.lines().enumerate() {
        let at = no + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let inner = line
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .ok_or((at, "bad section".to_string()))?;
            let parts: Vec<String> = inner.split('.').map(|s| s.trim().to_string()).collect();
            if parts.len() > 2 || parts.iter().any(|p| p.is_empty()) {
                return Err((at, format!("bad section: {line}")));
            }
            section = parts;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err((at, "expected key = value".to_string()));
        };
        let (key, value) = (key.trim(), value.trim());
        if section.is_empty() {
            if key == "strict" {
                strict = parse_bool(value, at)?;
                continue;
            }
            return Err((at, format!("unknown top-level key: {key:?}")));
        }
        if section.len() == 1 && key == "about" {
            provider_mut(&mut providers, &section[0]).about = Some(parse_string(value, at)?);
            continue;
        }
        if section.len() == 1 {
            return Err((at, format!("unknown provider key: {key:?}")));
        }
        let kind = kind_mut(&mut providers, &section[0], &section[1]);
        match key {
            "scope" => kind.scope = parse_string_array(value, at)?,
            "plain" => kind.plain = parse_bool(value, at)?,
            "file" => kind.file = parse_bool(value, at)?,
            "hint" => kind.hint = Some(parse_string(value, at)?),
            _ => return Err((at, format!("unknown kind key: {key:?}"))),
        }
    }
    Ok(Schema { strict, providers })
}

fn provider_mut<'a>(providers: &'a mut Vec<Provider>, name: &str) -> &'a mut Provider {
    if !providers.iter().any(|p| p.name == name) {
        providers.push(Provider {
            name: name.to_string(),
            about: None,
            kinds: Vec::new(),
        });
    }
    providers.iter_mut().find(|p| p.name == name).unwrap()
}

fn kind_mut<'a>(providers: &'a mut Vec<Provider>, provider: &str, kind: &str) -> &'a mut Kind {
    let list = &mut provider_mut(providers, provider).kinds;
    if !list.iter().any(|k| k.name == kind) {
        list.push(Kind {
            name: kind.to_string(),
            scope: vec!["SCOPE".to_string()],
            plain: false,
            file: false,
            hint: None,
        });
    }
    list.iter_mut().find(|k| k.name == kind).unwrap()
}

fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_str => escaped = true,
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

fn parse_string(value: &str, at: usize) -> Result<String, (usize, String)> {
    let inner = value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or((at, "expected a \"quoted string\"".to_string()))?;
    unescape(inner, at)
}

fn parse_string_array(value: &str, at: usize) -> Result<Vec<String>, (usize, String)> {
    let inner = value
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or((at, "expected [\"a\", \"b\"]".to_string()))?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_str = false;
    let mut escaped = false;
    for c in inner.chars() {
        if escaped {
            current.push('\\');
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_str => escaped = true,
            '"' => {
                in_str = !in_str;
                current.push(c);
            }
            ',' if !in_str => {
                items.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if in_str {
        return Err((at, "unterminated string in list".to_string()));
    }
    if !current.trim().is_empty() {
        items.push(current.trim().to_string());
    }
    items.iter().map(|item| parse_string(item, at)).collect()
}

fn unescape(inner: &str, at: usize) -> Result<String, (usize, String)> {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            _ => return Err((at, "bad escape".to_string())),
        }
    }
    Ok(out)
}

fn parse_bool(value: &str, at: usize) -> Result<bool, (usize, String)> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err((at, "expected true or false".to_string())),
    }
}

/// Teaches the schema one template: `PROVIDER:KIND:<VAR>...`. Returns true
/// when the provider table is new, plus the rendered template. Writes the
/// file atomically (appends new tables, keeps the rest byte for byte),
/// making the parent folder when missing instead of crashing.
pub fn define(
    path: &Path,
    template: &str,
    plain: bool,
    file: bool,
    hint: Option<&str>,
    about: Option<&str>,
) -> Result<(bool, String), Error> {
    let parts: Vec<&str> = template.split(':').collect();
    if parts.len() < 3 {
        return Err(Error::Schema(format!(
            "template {template:?} needs PROVIDER:KIND:<VAR>..."
        )));
    }
    let (provider, kind) = (parts[0], parts[1]);
    if provider.is_empty() || kind.is_empty() {
        return Err(Error::Schema(format!(
            "template {template:?} needs PROVIDER:KIND:<VAR>..."
        )));
    }
    let mut names = Vec::new();
    for var in &parts[2..] {
        if var.len() < 3 || !var.starts_with('<') || !var.ends_with('>') {
            return Err(Error::Schema(format!(
                "template {template:?} needs <VARS> after PROVIDER:KIND"
            )));
        }
        let name = &var[1..var.len() - 1];
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(Error::Schema(format!(
                "scope name {name:?} wants A-Z 0-9 _"
            )));
        }
        names.push(name.to_string());
    }
    let schema = Schema::load(path)?;
    if let Some(known) = schema.provider(provider)
        && known.kinds.iter().any(|k| k.name == kind)
    {
        return Err(Error::Schema(format!(
            "{provider} already has {kind}; delete the [{provider}.{kind}] table first"
        )));
    }
    let scope = format!(
        "[{}]",
        names
            .iter()
            .map(|n| format!("{n:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut lines = vec![format!("[{provider}.{kind}]"), format!("scope = {scope}")];
    if plain {
        lines.push("plain = true".to_string());
    }
    if file {
        lines.push("file = true".to_string());
    }
    if let Some(hint) = hint {
        lines.push(format!("hint = {hint:?}"));
    }
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let had_provider =
        text.contains(&format!("[{provider}]")) || text.contains(&format!("[{provider}."));
    let mut out = text;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !had_provider {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!("[{provider}]\n"));
        if let Some(about) = about {
            out.push_str(&format!("about = {about:?}\n"));
        }
        out.push('\n');
    }
    out.push_str(&lines.join("\n"));
    out.push('\n');
    est_core::store::write_atomic(path, out.as_bytes(), 0o644)?;
    Ok((!had_provider, self::template(provider, kind, &names)))
}

/// Forgets one template: removes its table, keeps everything else byte for
/// byte. The caller refuses first while addresses still use it.
pub fn undefine(path: &Path, provider: &str, kind: &str) -> Result<(), Error> {
    let schema = Schema::load(path)?;
    let known = schema
        .provider(provider)
        .and_then(|p| p.kinds.iter().find(|k| k.name == kind))
        .is_some();
    if !known {
        return Err(Error::Schema(format!("no template [{provider}.{kind}]")));
    }
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let header = format!("[{provider}.{kind}]");
    let mut out = Vec::new();
    let mut skipping = false;
    for line in text.lines() {
        let clean = strip_comment(line).trim();
        if clean == header {
            skipping = true;
            continue;
        }
        if skipping && clean.starts_with('[') {
            skipping = false;
        }
        if !skipping {
            out.push(line);
        }
    }
    let mut joined = out.join("\n");
    if !joined.is_empty() {
        joined.push('\n');
    }
    est_core::store::write_atomic(path, joined.as_bytes(), 0o644)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("est-vault-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const EXAMPLE: &str = "strict = true\n\
         \n\
         [GITHUB]\n\
         about = \"code hosting\"\n\
         \n\
         [GITHUB.PAT]\n\
         scope = [\"ACCOUNT\"]\n\
         hint = \"classic token\"\n\
         \n\
         [TELEGRAM.CHATID]\n\
         scope = [\"WHO\"]\n\
         plain = true\n";

    fn example() -> Schema {
        parse(EXAMPLE).unwrap()
    }

    #[test]
    fn parses_providers_and_kinds() {
        let schema = example();
        assert!(schema.strict);
        assert_eq!(schema.providers.len(), 2);
        let pat = schema.kind_rule("GITHUB:PAT:ME").unwrap();
        assert_eq!(pat.scope, vec!["ACCOUNT".to_string()]);
        assert_eq!(pat.hint.as_deref(), Some("classic token"));
        assert!(!pat.plain);
        assert!(schema.kind_rule("TELEGRAM:CHATID:ME").unwrap().plain);
    }

    #[test]
    fn missing_file_is_empty_schema() {
        let dir = scratch("schema-missing");
        let schema = Schema::load(&dir.join("nope.toml")).unwrap();
        assert!(!schema.strict);
        assert!(schema.providers.is_empty());
    }

    #[test]
    fn malformed_file_names_its_line() {
        let dir = scratch("schema-bad");
        let path = dir.join("bad.toml");
        std::fs::write(&path, "[GITHUB.PAT]\nscope = nope\n").unwrap();
        let err = Schema::load(&path).unwrap_err().to_string();
        assert!(err.contains("bad.toml:2:"), "{err}");
    }

    #[test]
    fn check_accepts_rejects_notes() {
        let schema = example();
        assert_eq!(check(&schema, "GITHUB:PAT:ME").unwrap(), None);
        assert!(check(&schema, "GITHUB:SSH:ME").is_err());
        assert!(check(&schema, "GITHUB:PAT").is_err());
        assert!(check(&schema, "GITHUB:PAT:A:B").is_err());
        assert!(check(&schema, "NOPE:PAT:ME").is_err());
        assert!(check(&schema, "SHORT").is_err());
    }

    #[test]
    fn check_notes_unknown_providers_unless_strict() {
        let schema = Schema {
            strict: false,
            providers: Vec::new(),
        };
        let note = check(&schema, "NOPE:PAT:ME").unwrap().unwrap();
        assert!(note.contains("NOPE"), "{note}");
    }

    #[test]
    fn define_appends_and_reloads() {
        let dir = scratch("schema-define");
        let path = dir.join("templates.toml");
        let (is_new, rendered) = define(&path, "ACME:KEY:<APP>", false, false, None, None).unwrap();
        assert!(is_new);
        assert_eq!(rendered, "ACME:KEY:<APP>");
        let schema = Schema::load(&path).unwrap();
        assert_eq!(check(&schema, "ACME:KEY:WEB").unwrap(), None);
        assert!(define(&path, "ACME:KEY:<APP>", false, false, None, None).is_err());
    }

    #[test]
    fn define_rejects_bad_templates() {
        let dir = scratch("schema-define-bad");
        let path = dir.join("templates.toml");
        assert!(define(&path, "ACME:KEY", false, false, None, None).is_err());
        assert!(define(&path, "ACME:KEY:APP", false, false, None, None).is_err());
        assert!(define(&path, "ACME:KEY:<app>", false, false, None, None).is_err());
    }

    #[test]
    fn undefine_removes_just_its_table() {
        let dir = scratch("schema-undefine");
        let path = dir.join("templates.toml");
        define(&path, "ACME:KEY:<APP>", false, false, None, None).unwrap();
        define(&path, "ACME:OTHER:<APP>", false, false, None, None).unwrap();
        undefine(&path, "ACME", "KEY").unwrap();
        let schema = Schema::load(&path).unwrap();
        assert!(
            schema
                .provider("ACME")
                .unwrap()
                .kinds
                .iter()
                .any(|k| k.name == "OTHER")
        );
        assert_eq!(check(&schema, "ACME:OTHER:WEB").unwrap(), None);
        assert!(undefine(&path, "ACME", "KEY").is_err());
    }
}
