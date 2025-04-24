use serde_json::json;
use std::collections::HashMap;
use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys};

#[test]
fn test_custom_claims() {
    let keys = JwtKeys::from_algorithm(JwtAlgorithm::HS256 {
        access_secret: "s1".to_string(),
        refresh_secret: "s2".to_string(),
    }).unwrap();

    let mut extra = HashMap::new();
    extra.insert("scope".to_string(), json!("read"));

    let token = keys.generate_access_token("uid99", 900, Some(extra.clone())).unwrap();

    let decoded = keys.decode_token(&token, "access").unwrap();

    assert_eq!(decoded.claims.sub, "uid99");
    assert_eq!(decoded.claims.extra.get("scope").unwrap(), "read");
}

#[test]
fn test_token_expiration() {
    let keys = JwtKeys::from_algorithm(JwtAlgorithm::HS256 {
        access_secret: "s1".to_string(),
        refresh_secret: "s2".to_string(),
    }).unwrap();

    let result =  match keys.generate_access_token("uid99", 1, None) {
        Ok(token) => {
            println!("Generated token: {}", token);
            token
        }
        Err(e) => {
            eprintln!("Error generating token: {}", e);
            return;
        }
    };

    std::thread::sleep(std::time::Duration::from_secs(2));

    let result = keys.decode_token(&result, "access");
    // eprintln!("{:?}", result.is_err());
    assert!(result.is_err(), "Token should have expired");
}
