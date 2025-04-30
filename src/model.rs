//! Defines data models used in JWT encoding and decoding processes.
//!
//! This module contains serializable structures for JWT claims and any additional metadata
//! that may be embedded into a token payload (e.g., user roles, custom fields).
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Represents the payload (claims) of a JSON Web Token (JWT).
///
/// This struct contains standard JWT claims such as `sub` (subject) and `exp` (expiration time),
/// along with a flexible map for any additional custom claims via `extra`.
///
/// The `extra` field is flattened during serialization and deserialization,
/// allowing arbitrary key-value pairs to be included at the top level of the JWT payload.
///
/// # Fields
/// * `sub` - Subject of the token, typically representing the user ID.
/// * `exp` - Expiration timestamp of the token, in seconds since Unix epoch.
/// * `extra` - A map for custom claims, allowing additional metadata to be added.
///
/// # Example
/// ```
/// use std::collections::HashMap;
/// use serde_json::json;
/// use lib_service_jwt::model::Claims;
///
/// let mut extra = HashMap::new();
/// extra.insert("role".to_string(), json!("admin"));
///
/// let claims = Claims {
///     sub: "user123".to_string(),
///     exp: 1_720_000_000,
///     extra,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

