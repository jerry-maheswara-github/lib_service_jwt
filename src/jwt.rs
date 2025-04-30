//! Provides core functionality for encoding and decoding JSON Web Tokens (JWT).
//!
//! This module handles the creation of access tokens, token validation, and decoding,
//! using the `jsonwebtoken` crate as the underlying implementation.
//!
use crate::model::Claims;
use jsonwebtoken::{encode, decode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use crate::errors::JwtServiceError;

type Result<T> = std::result::Result<T, JwtServiceError>;


/// The `JwtAlgorithm` enum defines the algorithm used for creating and verifying JWTs.
///
/// Currently, it supports only one variant:
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

    /// Decodes a JWT token and validates its claims.
    ///
    /// This function decodes a JWT token, validates its audience (`aud`), and checks if the token is expired. 
    /// It supports both access and refresh tokens, and the appropriate decoding key is chosen based on 
    /// the `token_type`. The audience (`aud`) is validated dynamically by accepting a `Vec<String>` 
    /// of audience names passed to the function.
    ///
    /// # Parameters
    /// - `token`: The JWT token string to decode. This token is expected to be in the correct format 
    ///   and signed with a valid key.
    /// - `token_type`: The type of the token, which should either be `"access"` or `"refresh"`. 
    ///   This determines which decoding key is used.
    /// - `audiences`: A vector of audience names that are expected to be present in the token's `aud` claim.
    ///   This vector will be used to validate the `aud` claim in the decoded token.
    ///
    /// # Returns
    /// - `Ok(TokenData<Claims>)`: If the token is successfully decoded and validated, this result will
    ///   contain the decoded token data and its claims.
    /// - `Err(Error)`: If there is an error during decoding, validation, or token expiration check, an error 
    ///   will be returned.
    ///
    /// # Errors
    /// The following errors may be returned:
    /// - `ErrorKind::InvalidToken`: If the token type is invalid or the token cannot be decoded.
    /// - `ErrorKind::InvalidAudience`: If the token audience is invalid or the token cannot be decoded.
    /// - `ErrorKind::InvalidIssuer`: If the token's issuer is invalid.
    /// - `ErrorKind::ExpiredSignature`: If the token's expiration (`exp`) has passed.
    /// - Any decoding or validation errors related to the JWT decoding process.
    ///
    fn decode_token(&self, token: &str, token_type: &str, audiences: Option<Vec<String>>) -> Result<TokenData<Claims>> ;

}

/// A wrapper around a JWT key pair implementation for generating and verifying tokens.
///
/// `JwtKeys` provides a unified interface to work with different JWT signing algorithms
/// by holding a boxed implementation of the `JwtKeyPair` trait. This allows flexibility in
/// switching between algorithms like RS256, HS256, etc., without changing application logic.
///
/// It acts as a high-level entry point for token generation (`generate_access_token`, `generate_refresh_token`)
/// and validation (`decode_token`) using the underlying key pair.
///
/// # Fields
/// * `backend` - A boxed trait object that implements the `JwtKeyPair` trait, providing
///   the actual logic for token encoding and decoding.
///
/// # Example
/// ```
/// use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys};
///     const DUMMY_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
/// MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDd2thu0emLDCJ/
/// kmhphMJ5BuwtFJjaLgumKSg4cCCc/3UwYV9WGq9EHF2KykCYfWmHspho5qrtM101
/// LF2EqVC0F1ReJIFPr3X0qfA/BRxkEnix62Ae7ukEtkFMQ9NiPIaADNdAP3D/+j7q
/// n+qhnWs+UgyQgKLbtWbG+9KMxcU2aXkMZXBIJp2Hbi48aY8jF/BkgNYsMZ05YbD/
/// AOZXYAoTZhCP38hdLrm0+yVLMA+vUjUDwzcaZn4/vJk8mgHHlfp0Y4pub3eKoQVk
/// IEDSLMQkV4757kaLeQ1p22pYGxo9UK9YntZuNle30ghQGPegQeA9bUyFiOct4CjU
/// Cni19XbpAgMBAAECggEAG1pU7qOP2qEWNx9bIzix7M+8hQ8HN3iPiXQv7XbES/G3
/// xk1tvoUkuyOPfuyny9qZN8NTxN89D2i9TbCDc+Hs6CoA22iUeY7QXr19uES44Y0L
/// d3g7OM/LnVVGi2YeD6cXDX5HzbfksT1ueL6wZC5Z9MGTTf+mKgDdbpwes1Tbl0pt
/// Rt3HbiRtN6cbkaozf0cnfxX2LYLJdxphxG3mTKWL4xM2ygvhbRTtlHDPsG8B/bHs
/// El2CkifjO4eaLxwDOAswZCx/XfBFvPtSmG51x6boL140atfkBoh6kBieZ9OjRBEW
/// taG+ElJ70GAKVBHty0b7KpDevUpRNZ6o28jqy67F9wKBgQD44fyN0uvmw/bX8r89
/// lXsKamuH0dhPFB2dveVpwbiDO6Rdp4reTjhdUf/JdIOZNqfkqey8JA0chvQ7/OJF
/// gbBMyDCgMVF3mVSrAuLKXya/UxEm5YCsJBNVeSZWwAOUncWN65ArkINxPo6nhEt5
/// qt6kC9fksi1gUPFZc2AMtFPXcwKBgQDkMv5wE3N6Q2Unox4blSoT1xzCSmnlp6OX
/// bzn+tV+clBRflxI76VKm91a0tJ6Ka2y8WPbFqL0l8d6GUY3Uh40yTM0TVpiYTmlG
/// 2EUAcF9B/jROist41rQCHKfhdqpbX5YcQTiE1ZopmPoK3/nvs+rla0gXLum1Fv1r
/// 8vYoCfeJMwKBgQDQSVhyXMW+L9xiZ64y3OnHEr8BQNY1gBE1FVpsgopnkb+B/ZhT
/// acT0HI7jyxXjYIFr9eXAoq8yY6L8nSvEnb+s0pEXT47td64LHHQuhylHTz54ffOM
/// nPhtPOGgEjws4UkW98CFJQFMAd2jRi1gGmcPhTXeGFuvUq5ZfRwyJaxRDwKBgA9l
/// uXFKfrIzNfIUuYVW7T3ld9VMPBT42LrxEFK1XjwsaauBgAN23NLTQZBz13azhOS4
/// g/4WQpz60u7xNcavVsGcGQJDB4zPTZ8wHIfJDURgqJrcFpqSshaqZFF8NkZwDqrd
/// Y7jiyMIhxk1Ri4W2+BR+xqB5098aLANKo31UHtWtAoGAGHh6Zc5qAFSPap235hRR
/// /xYkHwAXmenQw9Wjm3AUkqV26dql3XdUetcPuzwCqyboqNpMGrLW5pPRkF6E3osr
/// 6hfQ2SyC9KxuzpwHv17FNhUtkQI2sI1pKbx9+VG9n+znUEGJpo0yXD95SKJFcitE
/// bOE0gQzJ6bBfM15n0xaidbU=
/// -----END PRIVATE KEY-----";
/// 
///     const DUMMY_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
/// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3drYbtHpiwwif5JoaYTC
/// eQbsLRSY2i4LpikoOHAgnP91MGFfVhqvRBxdispAmH1ph7KYaOaq7TNdNSxdhKlQ
/// tBdUXiSBT6919KnwPwUcZBJ4setgHu7pBLZBTEPTYjyGgAzXQD9w//o+6p/qoZ1r
/// PlIMkICi27VmxvvSjMXFNml5DGVwSCadh24uPGmPIxfwZIDWLDGdOWGw/wDmV2AK
/// E2YQj9/IXS65tPslSzAPr1I1A8M3GmZ+P7yZPJoBx5X6dGOKbm93iqEFZCBA0izE
/// JFeO+e5Gi3kNadtqWBsaPVCvWJ7WbjZXt9IIUBj3oEHgPW1MhYjnLeAo1Ap4tfV2
/// 6QIDAQAB
/// -----END PUBLIC KEY-----";
/// let algo = JwtAlgorithm::RS256 {
///     access_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
///     access_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
///     refresh_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
///     refresh_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
/// };
///
/// let keys = JwtKeys::from_algorithm(algo).expect("Failed to create keys");
/// let token = keys.generate_access_token("key-id", "user123", 3600, None).unwrap();
/// ```
pub struct JwtKeys {
    backend: Box<dyn JwtKeyPair>,
}

impl JwtKeys {
    /// Creates an instance of `Self` from the provided JWT algorithm.
    ///
    /// This function takes a ['JwtAlgorithm'] as input and returns a ['Result'] containing
    /// the constructed instance if successful, or an error if any of the keys fail to parse.
    ///
    /// Currently, only the [`JwtAlgorithm::RS256`] variant is supported. It initializes
    /// the RSA key pair for both access and refresh tokens using the provided PEM-encoded keys.
    ///
    /// # Arguments
    ///
    /// * `algo` - A [`JwtAlgorithm`] containing the private and public RSA keys
    ///   for both access and refresh tokens.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` if all RSA keys are successfully parsed.
    /// * `Err` if any key fails to parse from the PEM data.
    ///
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

    pub fn decode_token(&self, token: &str, token_type: &str, audiences: Option<Vec<String>>) -> Result<TokenData<Claims>> {
        self.backend.decode_token(token, token_type, audiences)
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
        encode(&header, &claims, enc).map_err(JwtServiceError::from)
    }

    fn decode_token(&self, token: &str, token_type: &str, audiences: Option<Vec<String>>) -> Result<TokenData<Claims>> {
        let is_access = match token_type {
            "access" => true,
            "refresh" => false,
            _ => return Err(JwtServiceError::InvalidToken),
        };

        let dec_key: &DecodingKey = if is_access { &self.access_dec } else { &self.refresh_dec };

        let mut validation = Validation::new(Algorithm::RS256);

        if let Some(auds) = audiences {
            let aud_refs: Vec<&str> = auds.iter().map(String::as_str).collect();
            validation.set_audience(&aud_refs);
        }

        let decoded = decode::<Claims>(token, dec_key, &validation)
            .map_err(JwtServiceError::from)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtServiceError::InvalidToken)?
            .as_secs() as usize;
        if decoded.claims.exp < now {
            return Err(JwtServiceError::TokenExpired);
        }

        Ok(decoded)
    }
}

/// Returns the current Unix timestamp in seconds.
///
/// This function retrieves the current system time using `SystemTime::now()`
/// and calculates the duration since the Unix epoch (`UNIX_EPOCH`). If the system time
/// is somehow earlier than the epoch, it will default to `0` seconds.
///
/// # Example
/// ```
/// use lib_service_jwt::jwt::current_timestamp;
/// let ts = current_timestamp();
/// println!("Current timestamp: {}", ts);
/// ```
///
/// # Returns
/// * `usize` - The number of seconds since January 1, 1970 (Unix epoch).
pub fn current_timestamp() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs() as usize
}

/// Shortens a long token for display purposes by keeping the first and last 32 characters.
///
/// If the token's length is less than or equal to 64 characters, the original token is returned.
/// Otherwise, the token is truncated to the first 32 characters, followed by an ellipsis (`...`),
/// and then the last 32 characters.
///
/// This is useful for logging or UI display without revealing the entire token.
///
/// # Example
/// ```
/// use lib_service_jwt::jwt::shorten_token;
/// let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1In0.eyJzdWIiOiJ1aWQ5OSIsImV4cCI6MTc0NjMxOTUxNywicm9sZSI6ImFkbWluIn0.xhvjCu9RngRSwv7eJ5z7V7lHaubqUJVNa4xpA2HOICdttl_DsNrgO5QiddGik-IegNn782ixcMOraGI5DAmWQtxlG9_2AOWzQoSkqLlP0oYNZgZSOB0VZxSJ7XackUber0-D80BK_qy0hGIett4oRtImveKN3_awcSihsTI709FUndLbJ-W4tG2ZeOStZ2A-rvj4lbHX3bs1LLtxY6UJEfh8wK_Yo2v1yPA3i9oR0ZESHNZnRt3-fCKQ87nuDBYoyT-v5Oy2DWo-SWGYJfr9yOGe2Lp3ikXPeR9sqdK5QCs4y3iDKHubhY3GrEGE5HeRfULMI_KKt56CmZrYxInvzw";
/// let shortened = shorten_token(token);
/// println!("{}", shortened);
/// ```
///
/// # Arguments
/// * `token` - A string slice representing the token to be shortened.
///
/// # Returns
/// * `String` - The shortened token with the middle part replaced by `...` if it's too long.
pub fn shorten_token(token: &str) -> String {
    const LEN: usize = 32;
    if token.len() <= LEN * 2 {
        token.to_string()
    } else {
        format!("{}...{}", &token[..LEN], &token[token.len() - LEN..])
    }
}
