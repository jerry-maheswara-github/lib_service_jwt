#[cfg(test)]
mod tests {
    use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys};
    use serde_json::json;
    use std::collections::HashMap;

    const DUMMY_EC_ACCESS_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUEzYT3Vw5uSLDRcm
8yYPKMLt31Pj7b2TJ2kOTeDQPG6hRANCAARPOzAxwBcVSvPzB15dKbtU/ssxJ/ZD
JJORfbl29xjYZa1Rb0K9RadGxk9UU2p//Km6ByAAMqLrICAokIqIYpxc
-----END PRIVATE KEY-----
";
    const DUMMY_EC_ACCESS_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETzswMcAXFUrz8wdeXSm7VP7LMSf2
QySTkX25dvcY2GWtUW9CvUWnRsZPVFNqf/ypugcgADKi6yAgKJCKiGKcXA==
-----END PUBLIC KEY-----
";
    const DUMMY_EC_REFRESH_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFab1Ew5ps/lvpTLh
aK2j5vS9ltEjPOmgyJc+wtIjHoihRANCAASjSCJLBDYh95Z2n6FPDOrFQ1RlscX4
X78kvtPQJBWZcKe1QWnMOVn5hms48lXy67puRg0fOHbxTk148HaEQNZf
-----END PRIVATE KEY-----
";
    const DUMMY_EC_REFRESH_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo0giSwQ2IfeWdp+hTwzqxUNUZbHF
+F+/JL7T0CQVmXCntUFpzDlZ+YZrOPJV8uu6bkYNHzh28U5NePB2hEDWXw==
-----END PUBLIC KEY-----
";

    #[test]
    fn test_generate_and_decode_es256_token() {
        let algo = JwtAlgorithm::ES256 {
            access_private: DUMMY_EC_ACCESS_PRIVATE_KEY.as_bytes().to_vec(),
            access_public: DUMMY_EC_ACCESS_PUBLIC_KEY.as_bytes().to_vec(),
            refresh_private: DUMMY_EC_REFRESH_PRIVATE_KEY.as_bytes().to_vec(),
            refresh_public: DUMMY_EC_REFRESH_PUBLIC_KEY.as_bytes().to_vec(),
        };

        let keys = JwtKeys::from_algorithm(algo).expect("Failed to create JwtKeys");

        let kid = "some-key-id";
        let user_id = "user123";
        let expires_in = 60 * 60 * 24 * 30; // 30 days
        let mut extra = HashMap::new();

        let roles = vec!["admin", "user"];
        extra.insert("roles".to_string(), json!(roles));

        let audiences = Some(vec!["myApp1".to_string(), "myApp2".to_string()]);
        extra.insert("aud".to_string(), json!(audiences));

        let token = keys.generate_access_token(kid, user_id, expires_in, Some(extra.clone())).unwrap();

        println!("Token ={:?}", token);
        
        let decoded_token = keys.decode_token(&token, "access", audiences.clone()).unwrap();

        println!("Decoded Token Claims: {:?}", decoded_token.claims);

        assert_eq!(decoded_token.claims.sub, user_id);

        let maybe_roles: Vec<String> = decoded_token
            .claims
            .extra
            .get("roles")
            .and_then(|v| v.as_array())
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        assert_eq!(maybe_roles, vec!["admin", "user"]);

        let maybe_audiences: Option<Vec<String>> = decoded_token.claims.extra.get("aud")
            .and_then(|v| v.as_array())
            .map(|aud| aud.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());

        assert_eq!(maybe_audiences, Some(vec!["myApp1".to_string(), "myApp2".to_string()]));
    }

    #[test]
    fn test_generate_and_decode_es256_refresh_token() {
        let algo = JwtAlgorithm::ES256 {
            access_private: include_bytes!("../examples/ec/ec-access-private.pem").to_vec(),
            access_public: include_bytes!("../examples/ec/ec-access-public.pem").to_vec(),
            refresh_private: include_bytes!("../examples/ec/ec-refresh-private.pem").to_vec(),
            refresh_public: include_bytes!("../examples/ec/ec-refresh-public.pem").to_vec(),
        };

        let keys = JwtKeys::from_algorithm(algo).expect("Failed to create JwtKeys");

        let kid = "some-key-id";
        let user_id = "user123";
        let expires_in = 60 * 60 * 24 * 30; // 30 days
        let mut extra = HashMap::new();

        let roles = vec!["admin", "user"];
        extra.insert("roles".to_string(), json!(roles));

        let audiences = Some(vec!["myApp1".to_string(), "myApp2".to_string()]);
        extra.insert("aud".to_string(), json!(audiences));

        let token = keys.generate_refresh_token(kid, user_id, expires_in, Some(extra.clone())).unwrap();
        
        println!("Token ={:?}", token);

        let decoded_token = keys.decode_token(&token, "refresh", audiences.clone()).unwrap();

        println!("Decoded Refresh Token Claims: {:?}", decoded_token.claims);

        assert_eq!(decoded_token.claims.sub, user_id);

        let maybe_roles: Vec<String> = decoded_token
            .claims
            .extra
            .get("roles")
            .and_then(|v| v.as_array())
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        assert_eq!(maybe_roles, vec!["admin", "user"]);

        let maybe_audiences: Option<Vec<String>> = decoded_token.claims.extra.get("aud")
            .and_then(|v| v.as_array())
            .map(|aud| aud.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());

        assert_eq!(maybe_audiences, Some(vec!["myApp1".to_string(), "myApp2".to_string()]));
    }
}
