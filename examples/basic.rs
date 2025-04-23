use lib_service_jwt::{jwt::JwtKeys, model::Claims};
use serde_json::json;
use std::collections::HashMap;

fn main() {
    let keys = JwtKeys::new("access_secret_key", "refresh_secret_key");

    let mut extra = HashMap::new();
    extra.insert("role".to_string(), json!("admin"));
    extra.insert("user_id".to_string(), json!(123));

    let access_token = keys.generate_access_token("user_abc", Some(extra.clone())).unwrap();
    println!("Access Token: {}", access_token);

    let refresh_token = keys.generate_refresh_token("user_abc", Some(extra)).unwrap();
    println!("Refresh Token: {}", refresh_token);

    let decoded = keys.decode_token(&access_token, "access").unwrap();
    println!("Decoded Claims: {:?}", decoded.claims);
}
