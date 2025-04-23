use lib_service_jwt::jwt::JwtKeys;
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_custom_claims() {
    let keys = JwtKeys::new("s1", "s2");

    let mut extra = HashMap::new();
    extra.insert("scope".to_string(), json!("read"));

    let token = keys.generate_access_token("uid99", Some(extra.clone())).unwrap();
    let decoded = keys.decode_token(&token, "access").unwrap();

    assert_eq!(decoded.claims.sub, "uid99");
    assert_eq!(decoded.claims.extra.get("scope").unwrap(), "read");
}
