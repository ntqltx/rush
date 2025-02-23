use std::{fs, env};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::io::{Read, Write};

use aes_gcm::aead::{
    Aead, KeyInit, 
    generic_array::GenericArray
};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{Rng, RngCore};

use jsonwebtoken::{
    encode, Algorithm, 
    EncodingKey, Header
};
use jsonwebtoken::errors::{Error, ErrorKind};
use reqwest::Client;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use log::{info, warn, error};
use colored::Colorize;

// NOTE: if you are contributing this one, please contact with the owner to get json key
const CREDS_PATH: &str = "./src/configs/rpm-id-adminsdk.json";

#[derive(Serialize, Deserialize)]
struct AuthState {
    token: Option<String>,
    expires_at: Option<u64>,
}
#[derive(Serialize, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: String,
}
#[derive(Serialize, Deserialize)]
struct AuthTokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Token expired")]
    TokenExpired,
}
pub struct Authenticator {
    creds: ServiceAccountKey,
    client: Client,
    _state: Mutex<AuthState>,
    _refresh_interval: Duration,
}
impl Authenticator {
    pub fn new(refresh_interval: Duration) -> Result<Arc<Self>, AuthError> {
        let state = AuthState { token: None, expires_at: None };
        let creds_json = fs::read_to_string(CREDS_PATH)?;
        let creds: ServiceAccountKey = serde_json::from_str(&creds_json)?;

        Ok(Arc::new(Self {
            creds, client: Client::new(),
            _state: Mutex::new(state),
            _refresh_interval: refresh_interval,
        }))
    }

    fn generate_secret_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }
    
    // this needs to be re-wrote asap!!
    fn get_or_create_secret_key() -> [u8; 32] {
        let temp_dir = env::temp_dir();
        let mut existing_key_path: Option<PathBuf> = None;

        if let Ok(entries) = fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
                    if file_name.contains("-secretrpm") && file_name.ends_with(".key") {
                        existing_key_path = Some(path);
                        break;
                    }
                }
            }
        }
        if let Some(key_file_path) = existing_key_path {
            if let Ok(key) = fs::read(&key_file_path) {
                if key.len() == 32 {
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&key);
                    return key_array;
                }
            }
        }
        let guid = Uuid::new_v4();
        let key_filename = format!("{}-secretrpm.key", guid);
        let key_file_path = temp_dir.join(&key_filename);

        let new_key = Self::generate_secret_key();
        if let Err(e) = fs::write(&key_file_path, &new_key) {
            error!("Failed to write secret auth key: {}", e);
        }
        new_key
    }

    fn encrypt(data: &str, key: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let nonce: [u8; 12] = rand::rng().random();
        let nonce_arr = Nonce::from_slice(&nonce);
        
        let mut encrypted_data = cipher.encrypt(nonce_arr, data.as_bytes())?;
        let mut result = nonce.to_vec();
        result.append(&mut encrypted_data);
        Ok(result)
    }
    
    fn decrypt(encrypted_data: &[u8], key: &[u8]) -> Result<String, aes_gcm::Error> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        if encrypted_data.len() < 12 {
            return Err(aes_gcm::Error);
        }
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];
        
        let decrypted_data = cipher.decrypt(nonce, ciphertext)?;
        Ok(String::from_utf8_lossy(&decrypted_data).to_string())
    }

    pub async fn get_token(&self) -> Result<String, AuthError> {
        let temp_dir = env::temp_dir();
        let mut old_token_path: Option<PathBuf> = None;
        let mut old_token_state: Option<AuthState> = None;
    
        let mut secret_key = Self::get_or_create_secret_key();
        if let Ok(entries) = fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
                    if file_name.contains("-rpmkey") && file_name.ends_with(".tmp") {
                        old_token_path = Some(path.clone());

                        if let Ok(mut file) = fs::File::open(&path) {
                            let mut encrypted_contents = Vec::new();
                            if file.read_to_end(&mut encrypted_contents).is_ok() {
                                if let Ok(decrypted_data) = Self::decrypt(
                                    &encrypted_contents, &secret_key
                                ) {
                                    if let Ok(state) = serde_json::from_str::<AuthState>(&decrypted_data) {
                                        old_token_state = Some(state);
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        // why this code is actually so messy right now
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if let Some(ref state) = old_token_state {
            if let Some(ref token) = state.token {
                if let Some(expiration) = state.expires_at {
                    if now < expiration {
                        info!("{} {}", "Already authenticated".blue().bold(), "using existing token");
                        return Ok(token.clone());
                    } else {
                        warn!("{} {}", "Registry Token expired".bright_yellow(), "refreshing...");
                        if let Some(ref path) = old_token_path {
                            let _ = fs::remove_file(path);
                        }
                        if let Ok(entries) = fs::read_dir(&temp_dir) {
                            for entry in entries.flatten() {
                                let path = entry.path();
                                if path.file_name().map(|name| name == "-secretrpm.key").unwrap_or(false) {
                                    if let Err(e) = fs::remove_file(&path) {
                                        error!("Failed to delete secret key file: {}", e);
                                    }
                                    break;
                                }
                            }
                        }
                        secret_key = Self::get_or_create_secret_key();
                    }
                }
            }
        }
        let guid = Uuid::new_v4();
        let token_filename = format!("{}-rpmkey.tmp", guid);
        let token_file_path = temp_dir.join(&token_filename);

        let token = self.refresh_token().await?;
        let new_state = AuthState {
            token: Some(token.access_token.clone()),
            expires_at: Some(now + token.expires_in - 60),
            // expires_at: Some(now + 10), // 10 seconds expire for testing
        };
        let token_json = serde_json::to_string(&new_state)?;
        let encrypted_data = Self::encrypt(
            &token_json, &secret_key
        ).expect("Encryption failed");

        let mut file = fs::File::create(&token_file_path)?;
        file.write_all(&encrypted_data)?;
    
        info!("{} {}", "Authenticating".bright_cyan(), "to registry successfully finished");
        Ok(token.access_token)
    }

    async fn refresh_token(&self) -> Result<AuthTokenResponse, AuthError> {
        let jwt = generate_jwt_async(&self.creds).await?;
        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ];
        let response = self.client
            .post(&self.creds.token_uri)
            .form(&params).send().await?;

        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AuthError::AuthFailed(format!("HTTP error: {} - {}", status, error_text)));
        }
        let token_response: AuthTokenResponse = serde_json::from_str(&error_text)?;
        Ok(token_response)
    }
}

async fn generate_jwt_async(creds: &ServiceAccountKey) -> Result<String, AuthError> {
    #[derive(Serialize)]
    struct Claims {
        iss: String, scope: String,
        aud: String, exp: usize,
        iat: usize,
    }
    let iat = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::JwtError(Error::from(ErrorKind::InvalidIssuer)))?
        .as_secs() as usize;
    let exp = iat + 3600;

    let claims = Claims {
        iss: creds.client_email.clone(),
        scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        aud: creds.token_uri.clone(), exp, iat,
    };
    let key = EncodingKey::from_rsa_pem(creds.private_key.as_bytes())?;
    let jwt = encode(&Header::new(Algorithm::RS256), &claims, &key)?;
    Ok(jwt)
}