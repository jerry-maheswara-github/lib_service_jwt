use serde_json::json;
use std::collections::{HashMap, HashSet};
use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys, shorten_token, current_timestamp};

fn main() {
    let keys = JwtKeys::from_algorithm(JwtAlgorithm::RS256 {
        access_private: include_bytes!("rsa/access-private.pem").to_vec(),
        access_public: include_bytes!("rsa/access-public.pem").to_vec(),
        refresh_private: include_bytes!("rsa/refresh-private.pem").to_vec(),
        refresh_public: include_bytes!("rsa/refresh-public.pem").to_vec(),
    }).unwrap();

    let kid = "some-key-id";
    let user_id = "user123";
    let expires_in = 60 * 60 * 24 * 30;
    let mut extra = HashMap::new();
    
    // Add roles to the extra claims
    let roles = vec!["admin", "user"];
    extra.insert("roles".to_string(), json!(roles));

    // Add additional claims
    let email = "user123@example.com";
    let permissions = vec!["read", "write", "execute"];
    let nbf = current_timestamp(); 

    let mut audiences = HashSet::new();
    audiences.insert("my-app-123".to_string());
    audiences.insert("my-app-456".to_string());
    extra.insert("aud".to_string(), json!(audiences)); // Adding audience claim

    extra.insert("email".to_string(), json!(email));
    extra.insert("permissions".to_string(), json!(permissions));
    extra.insert("nbf".to_string(), json!(nbf)); // Adding audience claim

    let token = keys.generate_access_token(kid, user_id, expires_in, Some(extra.clone())).unwrap();
    let shorten_token = shorten_token(&token);
    println!("Generated Refresh Token: {} | shorten_token for logging: {}", token, shorten_token);

    let decoded = keys.decode_token(&token, "access").unwrap();

    println!("Decoded Token Claims: {:?}", decoded.claims);
    assert_eq!(decoded.claims.sub, "user123");
    
    let roles: Vec<String> = decoded.claims.extra.get("roles")
        .and_then(|v| v.as_array())
        .unwrap_or(&vec![])
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();

    assert!(roles.contains(&"admin".to_string()));

    let roles: Vec<String> = decoded.claims.extra.get("roles")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    assert_eq!(roles, vec!["admin", "user"]);
    
}
