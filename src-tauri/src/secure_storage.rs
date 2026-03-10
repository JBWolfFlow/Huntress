//! Secure Storage Module
//!
//! Provides encrypted storage for API keys and secrets using the application
//! data directory. Secrets are encrypted with AES-256-GCM using a key derived
//! via HKDF from a machine-specific identifier.
//!
//! ## Vault format (version 2)
//!
//! On-disk: a JSON file with a `version` field and an `entries` map.
//! Each entry value is base64( nonce || ciphertext || gcm_tag ), where:
//! - nonce   : 12 random bytes generated per encryption
//! - ciphertext + gcm_tag : AES-256-GCM output (ring appends the 16-byte tag)
//!
//! ## Backward compatibility (version 1)
//!
//! Version 1 vaults used XOR obfuscation.  When a version-1 vault is loaded,
//! each entry is decrypted with the legacy XOR path and immediately
//! re-encrypted with AES-256-GCM.  The vault is then promoted to version 2
//! and re-saved on the next write.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use ring::aead::{self, BoundKey, Nonce, NonceSequence, AES_256_GCM, NONCE_LEN};
use ring::error::Unspecified;
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

// ── Error type ────────────────────────────────────────────────────────────────

/// Error type for secure storage operations
#[derive(Debug, thiserror::Error)]
pub enum SecureStorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Encryption error: {0}")]
    Encryption(String),
}

impl serde::Serialize for SecureStorageError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// ── On-disk format ─────────────────────────────────────────────────────────

/// On-disk format: a map of key names to base64-encoded encrypted values.
///
/// `version == 2` entries are AES-256-GCM.
/// `version == 1` entries are legacy XOR (handled transparently on first load).
#[derive(Debug, Default, Serialize, Deserialize)]
struct Vault {
    version: u32,
    entries: HashMap<String, String>,
}

// ── Global vault state ──────────────────────────────────────────────────────

/// Global vault state, lazily loaded from disk on first access.
static VAULT: std::sync::LazyLock<Mutex<Option<Vault>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

// ── File paths ──────────────────────────────────────────────────────────────

/// Derive a storage path inside the app data directory.
fn vault_path() -> PathBuf {
    let base = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("huntress");
    std::fs::create_dir_all(&base).ok();
    base.join("vault.enc")
}

// ── Key derivation (HKDF) ────────────────────────────────────────────────────

/// Derive a 32-byte AES-256-GCM key from a machine-specific seed using HKDF-SHA256.
///
/// The input key material is the machine seed string encoded as UTF-8 bytes.
/// The info / context string binds the derived key to this specific usage.
fn derive_aes_key() -> Result<[u8; 32], SecureStorageError> {
    let seed = machine_seed();

    // HKDF salt: fixed but domain-separated so different apps won't share keys.
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"huntress-vault-v2-salt");

    // Extract step
    let prk = salt.extract(seed.as_bytes());

    // Expand step — produces exactly 32 bytes for AES-256
    let info: &[&[u8]] = &[b"huntress-aes-256-gcm-vault-key"];
    let mut key_bytes = [0u8; 32];
    prk.expand(info, MyLen(32))
        .map_err(|_| SecureStorageError::Encryption("HKDF expand failed".to_string()))?
        .fill(&mut key_bytes)
        .map_err(|_| SecureStorageError::Encryption("HKDF fill failed".to_string()))?;

    Ok(key_bytes)
}

/// A thin newtype so we can use `ring::hkdf::KeyType` for a runtime length.
struct MyLen(usize);

impl hkdf::KeyType for MyLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Build the machine-specific seed string (same inputs as the old XOR deriver).
fn machine_seed() -> String {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "huntress".to_string());
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "default".to_string());
    format!("huntress-vault-{}-{}", hostname, user)
}

// ── AES-256-GCM helpers ──────────────────────────────────────────────────────

/// A `NonceSequence` that yields a single fixed nonce and then errors.
///
/// Used for decryption where the nonce is read from the ciphertext prefix.
struct SingleNonce([u8; NONCE_LEN]);

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

/// Encrypt `plaintext` with AES-256-GCM.
///
/// Returns `base64( nonce(12) || ciphertext || tag(16) )`.
fn encrypt_value(plaintext: &str) -> Result<String, SecureStorageError> {
    let key_bytes = derive_aes_key()?;
    let rng = SystemRandom::new();

    // Generate a random nonce and keep a copy to prepend to the output.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| SecureStorageError::Encryption("nonce generation failed".to_string()))?;

    let unbound_key = aead::UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| SecureStorageError::Encryption("failed to create AES key".to_string()))?;

    let nonce_seq = SingleNonce(nonce_bytes);
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_seq);

    let mut in_out: Vec<u8> = plaintext.as_bytes().to_vec();
    // seal_in_place_append_tag appends the 16-byte GCM authentication tag.
    sealing_key
        .seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)
        .map_err(|_| SecureStorageError::Encryption("AES-GCM seal failed".to_string()))?;

    // Prepend the nonce so we can recover it on decryption.
    let mut output = Vec::with_capacity(NONCE_LEN + in_out.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&in_out);

    Ok(base64_encode(&output))
}

/// Decrypt a base64-encoded `nonce || ciphertext || tag` produced by [`encrypt_value`].
fn decrypt_value(encoded: &str) -> Result<String, SecureStorageError> {
    let key_bytes = derive_aes_key()?;

    let raw = base64_decode(encoded)
        .map_err(|e| SecureStorageError::Encryption(format!("base64 decode: {}", e)))?;

    if raw.len() < NONCE_LEN + 16 {
        return Err(SecureStorageError::Encryption(
            "ciphertext too short".to_string(),
        ));
    }

    let (nonce_slice, ciphertext_and_tag) = raw.split_at(NONCE_LEN);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce_slice);

    let unbound_key = aead::UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| SecureStorageError::Encryption("failed to create AES key".to_string()))?;

    let nonce_seq = SingleNonce(nonce_bytes);
    let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);

    let mut in_out: Vec<u8> = ciphertext_and_tag.to_vec();
    let plaintext_slice = opening_key
        .open_in_place(aead::Aad::empty(), &mut in_out)
        .map_err(|_| {
            SecureStorageError::Encryption("AES-GCM open failed (bad key or tampered data)".to_string())
        })?;

    String::from_utf8(plaintext_slice.to_vec())
        .map_err(|e| SecureStorageError::Encryption(format!("UTF-8 decode: {}", e)))
}

// ── Legacy XOR (version 1 backward compat) ───────────────────────────────────

/// XOR-based obfuscation key derived from the same machine seed.
/// Only used for reading version-1 vaults so they can be migrated.
fn derive_xor_key() -> Vec<u8> {
    let seed = machine_seed();
    let mut key = vec![0u8; 32];
    for (i, byte) in seed.bytes().enumerate() {
        key[i % 32] ^= byte;
        key[(i + 7) % 32] = key[(i + 7) % 32].wrapping_add(byte);
    }
    key
}

fn xor_cipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// Decrypt a version-1 (XOR) entry; returns the plaintext on success.
fn decrypt_value_v1(encoded: &str) -> Result<String, SecureStorageError> {
    let key = derive_xor_key();
    let encrypted = base64_decode(encoded)
        .map_err(|e| SecureStorageError::Encryption(format!("base64 decode (v1): {}", e)))?;
    let decrypted = xor_cipher(&encrypted, &key);
    String::from_utf8(decrypted)
        .map_err(|e| SecureStorageError::Encryption(format!("UTF-8 decode (v1): {}", e)))
}

// ── Base64 helpers (no external crate) ─────────────────────────────────────

/// Simple base64 encode (no external crate dependency).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Simple base64 decode.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const DECODE: [u8; 128] = {
        let mut table = [255u8; 128];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < alphabet.len() {
            table[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        table
    };

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut result = Vec::new();

    for chunk in bytes.chunks(4) {
        if chunk.is_empty() {
            break;
        }
        let vals: Vec<u8> = chunk
            .iter()
            .map(|&b| {
                if (b as usize) < 128 {
                    DECODE[b as usize]
                } else {
                    255
                }
            })
            .collect();

        if vals.iter().any(|&v| v == 255) {
            return Err("Invalid base64 character".to_string());
        }

        let n = vals.len();
        if n >= 2 {
            result.push((vals[0] << 2) | (vals[1] >> 4));
        }
        if n >= 3 {
            result.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if n >= 4 {
            result.push((vals[2] << 6) | vals[3]);
        }
    }

    Ok(result)
}

// ── Vault persistence ────────────────────────────────────────────────────────

/// Load vault from disk, migrating from version 1 if necessary.
///
/// If migration succeeds all entries are already re-encrypted; the caller is
/// responsible for saving the upgraded vault back to disk.
fn load_vault() -> Vault {
    let path = vault_path();
    if path.exists() {
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(mut vault) = serde_json::from_str::<Vault>(&data) {
                if vault.version == 1 {
                    // Migrate: decrypt each entry with XOR and re-encrypt with AES.
                    let mut migrated = HashMap::new();
                    let mut migration_ok = true;
                    for (k, v) in &vault.entries {
                        match decrypt_value_v1(v) {
                            Ok(plaintext) => match encrypt_value(&plaintext) {
                                Ok(new_enc) => {
                                    migrated.insert(k.clone(), new_enc);
                                }
                                Err(_) => {
                                    migration_ok = false;
                                    break;
                                }
                            },
                            Err(_) => {
                                migration_ok = false;
                                break;
                            }
                        }
                    }
                    if migration_ok {
                        vault.entries = migrated;
                        vault.version = 2;
                    }
                    // If migration failed we return the vault as-is (version 1).
                    // Subsequent reads will fail gracefully with Encryption errors.
                }
                return vault;
            }
        }
    }
    Vault {
        version: 2,
        entries: HashMap::new(),
    }
}

/// Save vault to disk.
fn save_vault(vault: &Vault) -> Result<(), SecureStorageError> {
    let path = vault_path();
    let data = serde_json::to_string_pretty(vault)?;
    std::fs::write(path, data)?;
    Ok(())
}

/// Ensure the vault is loaded into the global mutex.
fn ensure_vault() -> std::sync::MutexGuard<'static, Option<Vault>> {
    let mut guard = VAULT.lock().expect("vault mutex poisoned");
    if guard.is_none() {
        *guard = Some(load_vault());
    }
    guard
}

// ── Tauri Commands ──────────────────────────────────────────────────────────

/// Store a secret value under `key`, encrypted with AES-256-GCM.
///
/// # Examples
/// ```ignore
/// invoke("store_secret", { key: "anthropic_api_key", value: "sk-ant-..." })
/// ```
#[tauri::command]
pub async fn store_secret(key: String, value: String) -> Result<(), SecureStorageError> {
    let encrypted = encrypt_value(&value)?;
    let mut guard = ensure_vault();
    let vault = guard.as_mut().expect("vault initialized");
    vault.version = 2;
    vault.entries.insert(key, encrypted);
    save_vault(vault)?;
    Ok(())
}

/// Retrieve a secret by `key`.  Returns `KeyNotFound` if no such key exists.
///
/// # Examples
/// ```ignore
/// let key: String = invoke("get_secret", { key: "anthropic_api_key" }).await?;
/// ```
#[tauri::command]
pub async fn get_secret(key: String) -> Result<String, SecureStorageError> {
    let guard = ensure_vault();
    let vault = guard.as_ref().expect("vault initialized");
    let encrypted = vault
        .entries
        .get(&key)
        .ok_or_else(|| SecureStorageError::KeyNotFound(key))?;

    // Version-2 entries use AES-GCM.  If (after migration) we still have a
    // version-1 vault, fall back to XOR so the user can at least read their data.
    if vault.version == 1 {
        decrypt_value_v1(encrypted)
    } else {
        decrypt_value(encrypted)
    }
}

/// Delete the secret stored under `key`.
///
/// # Examples
/// ```ignore
/// invoke("delete_secret", { key: "anthropic_api_key" })
/// ```
#[tauri::command]
pub async fn delete_secret(key: String) -> Result<(), SecureStorageError> {
    let mut guard = ensure_vault();
    let vault = guard.as_mut().expect("vault initialized");
    vault.entries.remove(&key);
    save_vault(vault)?;
    Ok(())
}

/// List all stored secret keys (not values).
///
/// # Examples
/// ```ignore
/// let keys: Vec<String> = invoke("list_secret_keys").await?;
/// ```
#[tauri::command]
pub async fn list_secret_keys() -> Result<Vec<String>, SecureStorageError> {
    let guard = ensure_vault();
    let vault = guard.as_ref().expect("vault initialized");
    Ok(vault.entries.keys().cloned().collect())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AES-256-GCM ────────────────────────────────────────────────────────

    #[test]
    fn test_aes_gcm_roundtrip() {
        let plaintext = "sk-ant-api03-test-key-aes";
        let encrypted = encrypt_value(plaintext).expect("encrypt should succeed");
        let decrypted = decrypt_value(&encrypted).expect("decrypt should succeed");
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_gcm_different_nonces_each_call() {
        // Two encryptions of the same plaintext must produce different ciphertexts
        // because each call generates a fresh random nonce.
        let plaintext = "same-secret";
        let enc1 = encrypt_value(plaintext).expect("enc1");
        let enc2 = encrypt_value(plaintext).expect("enc2");
        assert_ne!(enc1, enc2, "nonces must differ between calls");
    }

    #[test]
    fn test_aes_gcm_tamper_detection() {
        let plaintext = "integrity-check";
        let encrypted = encrypt_value(plaintext).expect("encrypt");
        // Flip one byte in the raw blob to simulate tampering.
        let mut raw = base64_decode(&encrypted).expect("decode");
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        let tampered = base64_encode(&raw);
        assert!(
            decrypt_value(&tampered).is_err(),
            "tampered ciphertext must fail authentication"
        );
    }

    #[test]
    fn test_aes_gcm_empty_string() {
        let plaintext = "";
        let encrypted = encrypt_value(plaintext).expect("encrypt empty");
        let decrypted = decrypt_value(&encrypted).expect("decrypt empty");
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_gcm_unicode() {
        let plaintext = "密钥-🔑-api-key-unicode";
        let encrypted = encrypt_value(plaintext).expect("encrypt unicode");
        let decrypted = decrypt_value(&encrypted).expect("decrypt unicode");
        assert_eq!(plaintext, decrypted);
    }

    // ── HKDF key derivation ────────────────────────────────────────────────

    #[test]
    fn test_derive_aes_key_is_deterministic() {
        let k1 = derive_aes_key().expect("k1");
        let k2 = derive_aes_key().expect("k2");
        assert_eq!(k1, k2, "derived key must be deterministic");
        assert_eq!(k1.len(), 32, "key must be 32 bytes for AES-256");
    }

    // ── Legacy XOR (backward-compat) ─────────────────────────────────────

    #[test]
    fn test_xor_roundtrip() {
        let key = derive_xor_key();
        let plaintext = "super-secret-api-key-12345";
        let encrypted = xor_cipher(plaintext.as_bytes(), &key);
        let decrypted = xor_cipher(&encrypted, &key);
        assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
    }

    #[test]
    fn test_v1_decrypt_roundtrip() {
        // Simulate a v1 entry: XOR-encrypt then XOR-decrypt.
        let plaintext = "sk-ant-api03-test-key";
        let key = derive_xor_key();
        let ciphertext = xor_cipher(plaintext.as_bytes(), &key);
        let encoded = base64_encode(&ciphertext);
        let decrypted = decrypt_value_v1(&encoded).expect("v1 decrypt");
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_v1_to_v2_migration() {
        // Build a synthetic v1 vault in memory, run migration, verify entries
        // are now decryptable with AES-GCM decrypt_value.
        let plaintext = "migration-test-secret";
        let key = derive_xor_key();
        let ciphertext = xor_cipher(plaintext.as_bytes(), &key);
        let encoded = base64_encode(&ciphertext);

        let mut v1 = Vault {
            version: 1,
            entries: HashMap::new(),
        };
        v1.entries.insert("api_key".to_string(), encoded);

        // Manually run the migration logic that load_vault() would apply.
        let mut migrated = HashMap::new();
        for (k, v) in &v1.entries {
            let pt = decrypt_value_v1(v).expect("v1 decrypt");
            let new_enc = encrypt_value(&pt).expect("v2 encrypt");
            migrated.insert(k.clone(), new_enc);
        }
        let v2 = Vault {
            version: 2,
            entries: migrated,
        };

        // The migrated entry must decrypt successfully with the AES path.
        let recovered = decrypt_value(v2.entries.get("api_key").unwrap()).expect("v2 decrypt");
        assert_eq!(plaintext, recovered);
    }

    // ── Base64 ────────────────────────────────────────────────────────────

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, Huntress!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).expect("decode");
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_base64_empty() {
        let encoded = base64_encode(b"");
        let decoded = base64_decode(&encoded).expect("decode empty");
        assert!(decoded.is_empty());
    }

    // ── Encrypt output shape ──────────────────────────────────────────────

    #[test]
    fn test_encrypted_output_contains_nonce_prefix() {
        // The raw bytes must be at least NONCE_LEN(12) + GCM_TAG(16) = 28 bytes.
        let encrypted = encrypt_value("any secret").expect("encrypt");
        let raw = base64_decode(&encrypted).expect("decode");
        assert!(
            raw.len() >= NONCE_LEN + 16,
            "expected at least 28 bytes, got {}",
            raw.len()
        );
    }
}
