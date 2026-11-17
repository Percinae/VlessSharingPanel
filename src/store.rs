use std::{io, os::unix::fs::OpenOptionsExt, path::Path};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use chrono::{DateTime, Duration, Utc};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

pub fn write_secret(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::fs::OpenOptions;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    io::Write::write_all(&mut file, contents)?;
    file.sync_all()
}

pub fn open_db(path: &Path) -> rusqlite::Result<Connection> {
    let db = Connection::open(path)?;
    db.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
        CREATE TABLE IF NOT EXISTS shares (
          id INTEGER PRIMARY KEY,
          person TEXT NOT NULL, device TEXT NOT NULL, client_uuid TEXT NOT NULL,
          token_hash BLOB NOT NULL UNIQUE, password_hash TEXT NOT NULL,
          nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
          created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          max_views INTEGER, views INTEGER NOT NULL DEFAULT 0,
          revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE UNIQUE INDEX IF NOT EXISTS unique_active_uuid ON shares(client_uuid) WHERE revoked=0;",
    )?;
    Ok(db)
}

#[derive(Debug, Serialize)]
pub struct Share {
    pub id: i64,
    pub person: String,
    pub device: String,
    pub created_at: String,
    pub expires_at: String,
    pub max_views: Option<i64>,
    pub views: i64,
    pub revoked: bool,
}

pub struct Created {
    pub id: i64,
    pub link: String,
    pub password: String,
}

pub struct NewShare<'a> {
    pub person: &'a str,
    pub device: &'a str,
    pub uri: &'a str,
    pub days: i64,
    pub max_views: Option<i64>,
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn validate_vless(uri: &str) -> Result<String, String> {
    if uri.len() > 1800 || uri.contains(['\n', '\r']) {
        return Err("Недопустимый профиль или слишком длинный URI для QR".into());
    }
    let parsed = url::Url::parse(uri).map_err(|_| "Недопустимый VLESS URI")?;
    if parsed.scheme() != "vless" || parsed.host_str().is_none() || parsed.port().is_none() {
        return Err("Нужен полный vless:// URI с адресом и портом".into());
    }
    Uuid::parse_str(parsed.username()).map_err(|_| "В URI нет корректного UUID клиента")?;
    Ok(parsed.username().to_string())
}

pub fn create_share(
    db: &Connection,
    key: &[u8; 32],
    base_url: &str,
    new: NewShare<'_>,
) -> Result<Created, String> {
    let person = new.person.trim();
    let device = new.device.trim();
    let uri = new.uri;
    let days = new.days;
    let max_views = new.max_views;
    if person.is_empty()
        || person.chars().count() > 80
        || device.is_empty()
        || device.chars().count() > 80
    {
        return Err("Имя и устройство обязательны (до 80 символов)".into());
    }
    if !(1..=365).contains(&days) || max_views.is_some_and(|n| !(1..=1000).contains(&n)) {
        return Err("Недопустимый срок или лимит открытий".into());
    }
    let client_uuid = validate_vless(uri)?;
    let token = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
    let password = URL_SAFE_NO_PAD.encode(random_bytes::<18>());
    let pass_hash = hash_password(&password)?;
    let nonce = random_bytes::<24>();
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), uri.as_bytes())
        .map_err(|e| e.to_string())?;
    let now = Utc::now();
    let expires = now + Duration::days(days);
    db.execute("INSERT INTO shares (person, device, client_uuid, token_hash, password_hash, nonce, ciphertext, created_at, expires_at, max_views)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![person, device, client_uuid, token_hash(&token).as_slice(), pass_hash, nonce.as_slice(), ciphertext, now.to_rfc3339(), expires.to_rfc3339(), max_views])
        .map_err(|e| e.to_string())?;
    Ok(Created {
        id: db.last_insert_rowid(),
        link: format!("{}/s/{}", base_url.trim_end_matches('/'), token),
        password,
    })
}

pub fn list_shares(db: &Connection) -> rusqlite::Result<Vec<Share>> {
    let mut stmt = db.prepare("SELECT id, person, device, created_at, expires_at, max_views, views, revoked FROM shares ORDER BY id DESC")?;
    let rows = stmt.query_map([], |row| {
        Ok(Share {
            id: row.get(0)?,
            person: row.get(1)?,
            device: row.get(2)?,
            created_at: row.get(3)?,
            expires_at: row.get(4)?,
            max_views: row.get(5)?,
            views: row.get(6)?,
            revoked: row.get::<_, i64>(7)? != 0,
        })
    })?;
    rows.collect()
}

pub fn revoke_share(db: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(db.execute(
        "UPDATE shares SET revoked=1 WHERE id=?1 AND revoked=0",
        [id],
    )? == 1)
}

pub fn extend_share(db: &Connection, id: i64, days: i64) -> rusqlite::Result<bool> {
    if !(1..=365).contains(&days) {
        return Ok(false);
    }
    Ok(db.execute(
        "UPDATE shares SET expires_at=?1 WHERE id=?2 AND revoked=0",
        params![(Utc::now() + Duration::days(days)).to_rfc3339(), id],
    )? == 1)
}

pub fn redeem(db: &mut Connection, key: &[u8; 32], token: &str, password: &str) -> Option<String> {
    if token.len() != 43 || password.len() > 256 {
        return None;
    }
    let tx = db.transaction().ok()?;
    let record = tx.query_row("SELECT id, password_hash, nonce, ciphertext, expires_at, max_views, views, revoked FROM shares WHERE token_hash=?1",
        [token_hash(token).as_slice()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<i64>>(5)?, row.get::<_, i64>(6)?, row.get::<_, i64>(7)?))).optional().ok()??;
    let (id, pass_hash, nonce, ciphertext, expires, max_views, views, revoked) = record;
    let expiry = DateTime::parse_from_rfc3339(&expires).ok()?;
    if revoked != 0
        || expiry <= Utc::now()
        || max_views.is_some_and(|n| views >= n)
        || !verify_password(&pass_hash, password)
    {
        return None;
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .ok()?;
    let uri = String::from_utf8(plaintext).ok()?;
    tx.execute("UPDATE shares SET views=views+1 WHERE id=?1", [id])
        .ok()?;
    tx.commit().ok()?;
    Some(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const URI: &str = "vless://c1013308-9b32-48fa-bf64-22a5b69bf972@example.org:443?security=reality&type=tcp#friend";

    #[test]
    fn issue_redeem_limit_and_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sqlite3");
        let mut db = open_db(&path).unwrap();
        let key = random_bytes::<32>();
        let created = create_share(
            &db,
            &key,
            "https://example.org",
            NewShare {
                person: "Ivan",
                device: "iPhone",
                uri: URI,
                days: 1,
                max_views: Some(2),
            },
        )
        .unwrap();
        let token = created.link.rsplit('/').next().unwrap();
        assert_eq!(token.len(), 43);
        let bytes = fs::read(&path).unwrap();
        assert!(
            !bytes
                .windows(URI.len())
                .any(|window| window == URI.as_bytes())
        );
        assert!(
            !bytes
                .windows(token.len())
                .any(|window| window == token.as_bytes())
        );
        assert!(redeem(&mut db, &key, token, "wrong").is_none());
        assert_eq!(
            redeem(&mut db, &key, token, &created.password).as_deref(),
            Some(URI)
        );
        assert_eq!(
            redeem(&mut db, &key, token, &created.password).as_deref(),
            Some(URI)
        );
        assert!(redeem(&mut db, &key, token, &created.password).is_none());
        assert!(revoke_share(&db, created.id).unwrap());
        assert!(redeem(&mut db, &key, token, &created.password).is_none());
    }

    #[test]
    fn reject_invalid_uri() {
        assert!(validate_vless("https://example.org").is_err());
        assert!(validate_vless("vless://bad@example.org:443").is_err());
        assert!(
            validate_vless("vless://c1013308-9b32-48fa-bf64-22a5b69bf972@example.org:443\nextra")
                .is_err()
        );
    }

    #[test]
    fn expired_share_and_duplicate_uuid() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = open_db(&dir.path().join("test.sqlite3")).unwrap();
        let key = random_bytes::<32>();
        let new = || NewShare {
            person: "Ivan",
            device: "iPhone",
            uri: URI,
            days: 1,
            max_views: None,
        };
        let created = create_share(&db, &key, "https://example.org", new()).unwrap();
        assert!(create_share(&db, &key, "https://example.org", new()).is_err());
        db.execute(
            "UPDATE shares SET expires_at='2000-01-01T00:00:00Z' WHERE id=?1",
            [created.id],
        )
        .unwrap();
        let token = created.link.rsplit('/').next().unwrap();
        assert!(redeem(&mut db, &key, token, &created.password).is_none());
    }
}
