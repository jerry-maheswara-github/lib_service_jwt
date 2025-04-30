//! Defines internal error types for JWT operations and provides conversion
//! from `jsonwebtoken` crate errors into a unified `JwtServiceError`.
//!
//! The `JwtServiceError` enum encapsulates various failure modes related to
//! JSON Web Token handling, such as invalid tokens, signature errors, expired tokens,
//! or malformed cryptographic keys.
//!
//! It also includes an implementation of `From<jsonwebtoken::errors::Error>` to enable
//! seamless conversion from upstream JWT library errors into domain-specific error types.
//!
//! This module is typically used in services that require custom error handling
//! and gRPC-compatible response generation.
//!
//! ## Common Use
//! These errors can be mapped to gRPC responses using a trait like `ToStatus`,
//! or converted to logs/telemetry events for observability.
//!
use thiserror::Error;
use jsonwebtoken::errors::{Error as JwtError, ErrorKind as JwtErrorKind};

#[derive(Debug, Error)]
pub enum JwtServiceError {
    #[error("Invalid token")]
    InvalidToken,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid ECDSA key")]
    InvalidEcdsaKey,

    #[error("RSA signing failed")]
    RsaSigningFailed,

    #[error("Invalid RSA key")]
    InvalidRsaKey(String),

    #[error("Token has expired")]
    TokenExpired,

    #[error("Missing algorithm")]
    MissingAlgorithm,

    #[error("Missing required claim: {0}")]
    MissingClaim(String),

    #[error("Invalid issuer")]
    InvalidIssuer,

    #[error("Invalid audience")]
    InvalidAudience,

    #[error("Invalid subject")]
    InvalidSubject,

    #[error("Immature signature")]
    ImmatureSignature,

    #[error("Invalid algorithm")]
    InvalidAlgorithm,

    #[error("Invalid algorithm name")]
    InvalidAlgorithmName,

    #[error("Invalid key format")]
    InvalidKeyFormat,

    #[error("Base64 decoding error: {0}")]
    Base64Error(String),

    #[error("JSON error: {0}")]
    JsonError(String),

    #[error("UTF-8 error: {0}")]
    Utf8Error(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Unknown JWT error: {0}")]
    JwtError(String),

    #[error("System time error")]
    InvalidSystemTime,
}

impl From<JwtError> for JwtServiceError {
    fn from(err: JwtError) -> Self {
        match err.kind() {
            JwtErrorKind::InvalidToken => JwtServiceError::InvalidToken,
            JwtErrorKind::InvalidSignature => JwtServiceError::InvalidSignature,
            JwtErrorKind::InvalidEcdsaKey => JwtServiceError::InvalidEcdsaKey,
            JwtErrorKind::RsaFailedSigning => JwtServiceError::RsaSigningFailed,
            JwtErrorKind::InvalidRsaKey(e) => JwtServiceError::InvalidRsaKey(e.to_string()),
            JwtErrorKind::ExpiredSignature => JwtServiceError::TokenExpired,
            JwtErrorKind::MissingAlgorithm => JwtServiceError::MissingAlgorithm,
            JwtErrorKind::MissingRequiredClaim(claim) => JwtServiceError::MissingClaim(claim.to_string()),
            JwtErrorKind::InvalidIssuer => JwtServiceError::InvalidIssuer,
            JwtErrorKind::InvalidAudience => JwtServiceError::InvalidAudience,
            JwtErrorKind::InvalidSubject => JwtServiceError::InvalidSubject,
            JwtErrorKind::ImmatureSignature => JwtServiceError::ImmatureSignature,
            JwtErrorKind::InvalidAlgorithm => JwtServiceError::InvalidAlgorithm,
            JwtErrorKind::InvalidAlgorithmName => JwtServiceError::InvalidAlgorithmName,
            JwtErrorKind::InvalidKeyFormat => JwtServiceError::InvalidKeyFormat,
            JwtErrorKind::Base64(e) => JwtServiceError::Base64Error(e.to_string()),
            JwtErrorKind::Json(e) => JwtServiceError::JsonError(e.to_string()),
            JwtErrorKind::Utf8(e) => JwtServiceError::Utf8Error(e.to_string()),
            JwtErrorKind::Crypto(e) => JwtServiceError::CryptoError(e.to_string()),
            _ => JwtServiceError::JwtError(err.to_string()),
        }
    }
}
