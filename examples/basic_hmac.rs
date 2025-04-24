use serde_json::json;
use std::collections::HashMap;
use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys};

fn main() {
    let keys = JwtKeys::from_algorithm(JwtAlgorithm::HS256 {
        access_secret: "s1".to_string(),
        refresh_secret: "s2".to_string(),
    }).unwrap();

    let mut extra = HashMap::new();
    extra.insert("scope".to_string(), json!("read"));

    let token = keys.generate_access_token("uid99", 900, Some(extra.clone())).unwrap();
    println!("Generated Access Token: {}", token);

    let decoded = keys.decode_token(&token, "access").unwrap();

    println!("Decoded Token Claims: {:?}", decoded.claims);
    assert_eq!(decoded.claims.sub, "uid99");
    assert_eq!(decoded.claims.extra.get("scope").unwrap(), "read");
}
