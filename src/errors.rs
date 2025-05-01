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
use jsonwebtoken::errors::{Error as JwtError, ErrorKind as JwtErrorKind};

/// Represents errors that can occur during JWT processing and validation.
#[derive(Debug, thiserror::Error)]
pub enum JwtServiceError {
    /// The token is malformed, invalid, or could not be decoded.
    #[error("Invalid token")]
    InvalidToken,

    /// The token's signature is invalid or has been tampered with.
    #[error("Invalid signature")]
    InvalidSignature,

    /// The provided ECDSA key is not valid or cannot be parsed.
    #[error("Invalid ECDSA key")]
    InvalidEcdsaKey,

    /// Signing with RSA failed during token creation.
    #[error("RSA signing failed")]
    RsaSigningFailed,

    /// The RSA key provided is invalid or cannot be parsed.
    #[error("Invalid RSA key")]
    InvalidRsaKey(String),

    /// The token has expired based on the `exp` claim.
    #[error("Token has expired")]
    TokenExpired,

    /// No signing algorithm was specified or found.
    #[error("Missing algorithm")]
    MissingAlgorithm,

    /// A required claim is missing from the token payload.
    #[error("Missing required claim: {0}")]
    MissingClaim(String),

    /// The issuer (`iss` claim) is invalid or does not match expected value.
    #[error("Invalid issuer")]
    InvalidIssuer,

    /// The audience (`aud` claim) is invalid or not accepted.
    #[error("Invalid audience")]
    InvalidAudience,

    /// The subject (`sub` claim) is invalid or not recognized.
    #[error("Invalid subject")]
    InvalidSubject,

    /// The token is not yet valid (`nbf` claim is in the future).
    #[error("Immature signature")]
    ImmatureSignature,

    /// The specified or inferred algorithm is not supported or recognized.
    #[error("Invalid algorithm")]
    InvalidAlgorithm,

    /// The algorithm name provided is not a valid or recognized name.
    #[error("Invalid algorithm name")]
    InvalidAlgorithmName,

    /// The key format is invalid (e.g., PEM/DER parsing failed).
    #[error("Invalid key format")]
    InvalidKeyFormat,

    /// An error occurred while decoding a Base64-encoded field.
    #[error("Base64 decoding error: {0}")]
    Base64Error(String),

    /// Failed to parse or serialize a JWT payload as JSON.
    #[error("JSON error: {0}")]
    JsonError(String),

    /// UTF-8 decoding failed for a string in the token.
    #[error("UTF-8 error: {0}")]
    Utf8Error(String),

    /// A general cryptographic error occurred (e.g., during signing or verification).
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// A non-specific error related to JWT processing.
    #[error("Unknown JWT error: {0}")]
    JwtError(String),

    /// The system clock is invalid or failed to retrieve time.
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
