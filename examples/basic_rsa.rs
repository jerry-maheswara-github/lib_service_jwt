use serde_json::json;
use std::collections::HashMap;
use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys, shorten_token};

fn main() {
    let keys = JwtKeys::from_algorithm(JwtAlgorithm::RS256 {
        access_private: include_bytes!("rsa/private_key.pem").to_vec(),
        access_public: include_bytes!("rsa/public_key.pem").to_vec(),
        refresh_private: include_bytes!("rsa/private_key.pem").to_vec(),
        refresh_public: include_bytes!("rsa/public_key.pem").to_vec(),
    }).unwrap();

    let mut extra = HashMap::new();
    extra.insert("role".to_string(), json!("admin"));

    let token = keys.generate_refresh_token("uid99", 60 * 60 * 24 * 7, Some(extra.clone())).unwrap();
    let pendek = shorten_token(&token);
    println!("Generated Refresh Token: {}, pendek: {}", token, pendek);

    let decoded = keys.decode_token(&token, "refresh").unwrap();

    println!("Decoded Token Claims: {:?}", decoded.claims);
    assert_eq!(decoded.claims.sub, "uid99");
    assert_eq!(decoded.claims.extra.get("role").unwrap(), "admin");
}
