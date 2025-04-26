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

/// The `JwtKeyPair` trait defines the methods for generating and decoding JWTs.
///
/// It is intended to be implemented by types that manage JWT key pairs (either symmetric or asymmetric),
/// allowing them to generate and decode JWT tokens for both access and refresh tokens.
pub trait JwtKeyPair: Send + Sync {
    /// Generates a JWT token with the given claims and an expiration time.
    ///
    /// - `sub`: The subject (usually the user ID or identifier) for the JWT.
    /// - `expires_in`: The expiration time for the JWT in seconds.
    /// - `extra`: Optional extra custom claims to include in the JWT.
    /// - `is_access`: Boolean indicating whether the token is an access token (`true`) or a refresh token (`false`).
    ///
    /// Returns a `Result<String>`, where the `String` is the generated JWT token.
    ///
    /// # Errors
    /// If there is an error generating the token (e.g., due to key issues), it returns an `Err` result.
    fn generate_token(&self, kid: &str, sub: &str, expires_in: usize, extra: Option<HashMap<String, Value>>, is_access: bool) -> Result<String>;

    /// Decodes a JWT token and returns its claims.
    ///
    /// - `token`: The JWT token string to decode.
    /// - `is_access`: Boolean indicating whether the token is an access token (`true`) or a refresh token (`false`).
    ///
    /// Returns a `Result<TokenData<Claims>>`, where `TokenData<Claims>` contains the decoded claims data.
    ///
    /// # Errors
    /// If the token cannot be decoded (e.g., due to an invalid token or signature), it returns an `Err` result.
    fn decode_token(&self, token: &str, token_type: &str) -> Result<TokenData<Claims>>;
}

pub struct JwtKeys {
    backend: Box<dyn JwtKeyPair>,
}

impl JwtKeys {
    pub fn from_algorithm(algo: JwtAlgorithm) -> Result<Self> {
        match algo { 
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

    pub fn generate_access_token(&self, kid: &str, user_id: &str, expires_in: usize, extra: Option<HashMap<String, Value>>) -> Result<String> {
        self.backend.generate_token(kid, user_id, expires_in, extra, true)
    }

    pub fn generate_refresh_token(&self, kid: &str, user_id: &str, expires_in: usize, extra: Option<HashMap<String, Value>>) -> Result<String> {
        self.backend.generate_token(kid, user_id, expires_in, extra, false)
    }

    pub fn decode_token(&self, token: &str, token_type: &str) -> Result<TokenData<Claims>> {
        self.backend.decode_token(token, token_type)
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
    fn generate_token(&self, kid: &str, sub: &str, expires_in: usize, extra: Option<HashMap<String, Value>>, is_access: bool) -> Result<String> {
        let exp = current_timestamp() + expires_in;
        let claims = Claims {
            sub: sub.to_string(),
            exp,
            extra: extra.unwrap_or_default(),
        };
        
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());

        let enc = if is_access { &self.access_enc } else { &self.refresh_enc };
        encode(&header, &claims, enc)
    }

    fn decode_token(&self, token: &str, token_type: &str) -> Result<TokenData<Claims>> {
        let is_access = match token_type {
            "access" => true,
            "refresh" => false,
            _ => {
                return Err(Error::from(ErrorKind::InvalidToken));
            }
        };
        let dec = if is_access { &self.access_dec } else { &self.refresh_dec };
        let decoded = decode::<Claims>(token, dec, &Validation::new(Algorithm::RS256))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::from(ErrorKind::InvalidIssuer))? 
            .as_secs() as usize;

        if decoded.claims.exp < now {
            return Err(Error::from(ErrorKind::ExpiredSignature));
        }

        Ok(decoded)
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
