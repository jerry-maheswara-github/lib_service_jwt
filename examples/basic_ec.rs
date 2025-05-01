use std::collections::HashMap;
use serde_json::json;
use lib_service_jwt::errors::JwtServiceError;
use lib_service_jwt::jwt::{current_timestamp, shorten_token, JwtAlgorithm, JwtKeys};

fn main() -> Result<(), JwtServiceError> {
    let keys = JwtKeys::from_algorithm(JwtAlgorithm::ES256 {
        access_private: include_bytes!("ec/ec-access-private.pem").to_vec(),
        access_public: include_bytes!("ec/ec-access-public.pem").to_vec(),
        refresh_private: include_bytes!("ec/ec-refresh-private.pem").to_vec(),
        refresh_public: include_bytes!("ec/ec-refresh-public.pem").to_vec(),
    })?;

    let kid = "ec-key-id";
    let user_id = "user123";
    let expires_in = 60 * 60 * 24 * 30; // 30 days
    let mut extra = HashMap::new();

    let roles = vec!["admin", "user"];
    extra.insert("roles".to_string(), json!(roles));

    let email = "user123@example.com";
    let permissions = vec!["read", "write", "execute"];
    let iat = current_timestamp();
    let nbf = current_timestamp();

    let audiences = Some(vec!["myApp1".to_string(), "myApp2".to_string()]);
    extra.insert("aud".to_string(), json!(audiences.clone()));
    extra.insert("email".to_string(), json!(email));
    extra.insert("permissions".to_string(), json!(permissions));
    extra.insert("iat".to_string(), json!(iat));
    extra.insert("nbf".to_string(), json!(nbf));
    
    let token = keys.generate_access_token(kid, user_id, expires_in, Some(extra.clone()))?;
    let shorten_token = shorten_token(&token);
    println!("Generated Access Token: {} | Short: {}", token, shorten_token);

    let decoded = keys.decode_token(&token, "access", audiences.clone())?;

    println!("Decoded Token Claims: {:?}", decoded.claims);
    assert_eq!(decoded.claims.sub, user_id);

    let maybe_email = decoded.claims.extra.get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JwtServiceError::JsonError("Missing or invalid email in token".to_string()))?;

    assert_eq!(maybe_email, "user123@example.com");

    let roles: Vec<String> = decoded.claims.extra.get("roles")
        .and_then(|v| v.as_array())
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    assert_eq!(roles, vec!["admin", "user"]);

    Ok(())
}
