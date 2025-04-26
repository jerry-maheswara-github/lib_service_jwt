use crate::model::Claims;
use jsonwebtoken::{encode, decode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, errors::{Error, ErrorKind, Result}};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

/// The `JwtAlgorithm` enum defines the algorithm used for creating and verifying JWTs.
///
/// It has two variants:
/// - **HS256**: Uses a secret key (string) for signing the JWT.
/// - **RS256**: Uses a pair of RSA public and private keys for signing and verifying the JWT.
pub enum JwtAlgorithm {
    /// HS256 algorithm uses a secret key (string) to sign the JWT.
    ///
    /// - `access_secret`: The secret key for signing the access token.
    /// - `refresh_secret`: The secret key for signing the refresh token.
    HS256 {
        /// Secret key for signing the access token
        access_secret: String,
        /// Secret key for signing the refresh token
        refresh_secret: String,
    },

    /// RS256 algorithm uses a pair of RSA private and public keys to sign and verify the JWT.
    ///
    /// - `access_private`: The private key for signing the access token.
    /// - `access_public`: The public key for verifying the access token.
    /// - `refresh_private`: The private key for signing the refresh token.
    /// - `refresh_public`: The public key for verifying the refresh token.
    RS256 {
        /// Private key for signing the access token
        access_private: Vec<u8>,
        /// Public key for verifying the access token
        access_public: Vec<u8>,
        /// Private key for signing the refresh token
        refresh_private: Vec<u8>,
        /// Public key for verifying the refresh token
        refresh_public: Vec<u8>,
    },
}

trait JwtKeyPair: Send + Sync {
    fn generate_token(&self, sub: &str, expires_in: usize, extra: Option<HashMap<String, Value>>, is_access: bool) -> Result<String>;

    fn decode_token(&self, token: &str, is_access: bool) -> Result<TokenData<Claims>>;
}

pub struct JwtKeys {
    backend: Box<dyn JwtKeyPair>,
}

impl JwtKeys {
    pub fn from_algorithm(algo: JwtAlgorithm) -> Result<Self> {
        match algo {
            JwtAlgorithm::HS256 { access_secret, refresh_secret } => Ok(Self {
                backend: Box::new(Hs256KeyPair { access_secret, refresh_secret }),
            }),
            JwtAlgorithm::RS256 {
                access_private,
                access_public,
                refresh_private,
                refresh_public,
            } => Ok(Self {
                backend: Box::new(Rs256KeyPair {
                    access_enc: EncodingKey::from_rsa_pem(&access_private)?,
                    access_dec: DecodingKey::from_rsa_pem(&access_public)?,
                    refresh_enc: EncodingKey::from_rsa_pem(&refresh_private)?,
                    refresh_dec: DecodingKey::from_rsa_pem(&refresh_public)?,
                }),
            }),
        }
    }

    pub fn generate_access_token(&self, user_id: &str, expires_in: usize, extra: Option<HashMap<String, Value>>) -> Result<String> {
        self.backend.generate_token(user_id, expires_in, extra, true)
    }

    pub fn generate_refresh_token(&self, user_id: &str, expires_in: usize, extra: Option<HashMap<String, Value>>) -> Result<String> {
        self.backend.generate_token(user_id, expires_in, extra, false)
    }

    pub fn decode_token(&self, token: &str, token_type: &str) -> Result<TokenData<Claims>> {
        let is_access = match token_type {
            "access" => true,
            "refresh" => false,
            _ => {
                return Err(Error::from(ErrorKind::InvalidToken));
            }
        };

        let decoded = self.backend.decode_token(token, is_access)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::from(ErrorKind::InvalidIssuer))? // fallback error
            .as_secs() as usize;

        if decoded.claims.exp < now {
            return Err(Error::from(ErrorKind::ExpiredSignature));
        }

        Ok(decoded)
    }
}

/// ========================== HS256 Backend ==========================
struct Hs256KeyPair {
    access_secret: String,
    refresh_secret: String,
}

impl JwtKeyPair for Hs256KeyPair {
    fn generate_token(&self, sub: &str, expires_in: usize, extra: Option<HashMap<String, Value>>, is_access: bool) -> Result<String> {
        let exp = current_timestamp() + expires_in;
        let claims = Claims {
            sub: sub.to_string(),
            exp,
            extra: extra.unwrap_or_default(),
        };

        let secret = if is_access {
            &self.access_secret
        } else {
            &self.refresh_secret
        };

        encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret.as_bytes()))
    }

    fn decode_token(&self, token: &str, is_access: bool) -> Result<TokenData<Claims>> {
        let secret = if is_access {
            &self.access_secret
        } else {
            &self.refresh_secret
        };

        decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::new(Algorithm::HS256))
    }
}

/// ========================== RS256 Backend ==========================
struct Rs256KeyPair {
    access_enc: EncodingKey,
    access_dec: DecodingKey,
    refresh_enc: EncodingKey,
    refresh_dec: DecodingKey,
}

impl JwtKeyPair for Rs256KeyPair {
    fn generate_token(&self, sub: &str, expires_in: usize, extra: Option<HashMap<String, Value>>, is_access: bool) -> Result<String> {
        let exp = current_timestamp() + expires_in;
        let claims = Claims {
            sub: sub.to_string(),
            exp,
            extra: extra.unwrap_or_default(),
        };

        let enc = if is_access { &self.access_enc } else { &self.refresh_enc };
        encode(&Header::new(Algorithm::RS256), &claims, enc)
    }

    fn decode_token(&self, token: &str, is_access: bool) -> Result<TokenData<Claims>> {
        let dec = if is_access { &self.access_dec } else { &self.refresh_dec };
        decode::<Claims>(token, dec, &Validation::new(Algorithm::RS256))
    }
}

pub fn current_timestamp() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs() as usize
}

pub fn shorten_token(token: &str) -> String {
    const LEN: usize = 32;
    if token.len() <= LEN * 2 {
        token.to_string()
    } else {
        format!("{}...{}", &token[..LEN], &token[token.len() - LEN..])
    }
}
