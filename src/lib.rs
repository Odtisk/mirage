use wasm_bindgen::prelude::*;
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, DecodeRsaPrivateKey, DecodeRsaPublicKey}, Pkcs1v15Encrypt};
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Key}};
use aes_gcm::aead::generic_array::GenericArray;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use getrandom::getrandom;

// Включаем поддержку случайной генерации в WASM
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

// Структуры для передачи данных
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    #[wasm_bindgen(getter_with_clone)]
    pub private_key: String,
    #[wasm_bindgen(getter_with_clone)]
    pub public_key: String,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    #[wasm_bindgen(getter_with_clone)]
    pub ciphertext: String,
    #[wasm_bindgen(getter_with_clone)]
    pub nonce: String,
}

// ==================== СИММЕТРИЧНОЕ ШИФРОВАНИЕ (AES-256-GCM) ====================

#[wasm_bindgen]
pub fn generate_symmetric_key() -> String {
    let mut key = [0u8; 32]; // 256 бит для AES-256
    getrandom(&mut key).expect("Failed to generate random key");
    hex::encode(key)
}

#[wasm_bindgen]
pub fn encrypt_symmetric(plaintext: &str, key_hex: &str) -> Result<String, JsValue> {
    let key_bytes = hex::decode(key_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes (256 bits)"));
    }
    
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // Генерируем случайный nonce (12 байт для AES-GCM)
    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let nonce = GenericArray::from_slice(&nonce_bytes);
    
    // Шифруем
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Возвращаем JSON с ciphertext и nonce
    let result = EncryptedData {
        ciphertext: hex::encode(ciphertext),
        nonce: hex::encode(nonce_bytes),
    };
    
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_symmetric(encrypted_json: &str, key_hex: &str) -> Result<String, JsValue> {
    let encrypted: EncryptedData = serde_json::from_str(encrypted_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let key_bytes = hex::decode(key_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes (256 bits)"));
    }
    
    let ciphertext = hex::decode(encrypted.ciphertext)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let nonce_bytes = hex::decode(encrypted.nonce)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    
    // Расшифровываем
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    String::from_utf8(plaintext_bytes).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ==================== АСИММЕТРИЧНОЕ ШИФРОВАНИЕ (RSA-2048) ====================

#[wasm_bindgen]
pub fn generate_asymmetric_keypair() -> Result<String, JsValue> {
    let mut rng = OsRng;
    
    // Генерируем приватный ключ (2048 бит)
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Получаем публичный ключ
    let public_key = RsaPublicKey::from(&private_key);
    
    // Конвертируем в PEM формат (DER в base64)
    let private_key_pem = private_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let public_key_pem = public_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Возвращаем как JSON
    let keypair = KeyPair {
        private_key: private_key_pem.to_string(),
        public_key: public_key_pem.to_string(),
    };
    
    serde_json::to_string(&keypair).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn encrypt_asymmetric(plaintext: &str, public_key_pem: &str) -> Result<String, JsValue> {
    let public_key = RsaPublicKey::from_pkcs1_pem(public_key_pem)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let mut rng = OsRng;
    
    // RSA имеет ограничение на размер шифруемых данных
    // Для 2048 бит максимально ~245 байт
    if plaintext.len() > 245 {
        return Err(JsValue::from_str("Plaintext too long for RSA-2048 (max 245 bytes)"));
    }
    
    // Шифруем
    let ciphertext = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext.as_bytes())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    Ok(hex::encode(ciphertext))
}

#[wasm_bindgen]
pub fn decrypt_asymmetric(ciphertext_hex: &str, private_key_pem: &str) -> Result<String, JsValue> {
    let private_key = RsaPrivateKey::from_pkcs1_pem(private_key_pem)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let ciphertext = hex::decode(ciphertext_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Расшифровываем
    let plaintext_bytes = private_key
        .decrypt(Pkcs1v15Encrypt, &ciphertext)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    String::from_utf8(plaintext_bytes).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ==================== ДОПОЛНИТЕЛЬНЫЕ УТИЛИТЫ ====================

#[wasm_bindgen]
pub fn hash_sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[wasm_bindgen]
pub fn generate_random_bytes(count: usize) -> Result<String, JsValue> {
    let mut bytes = vec![0u8; count];
    getrandom(&mut bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(bytes))
}

// Простая функция hello world для проверки
#[wasm_bindgen]
pub fn hello_world() -> String {
    "Hello from Rust WASM Crypto!".to_string()
}