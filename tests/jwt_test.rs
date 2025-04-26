use lib_service_jwt::jwt::{JwtAlgorithm, JwtKeys};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;

    // Dummy keys (Private and Public) in PEM format
    const DUMMY_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDd2thu0emLDCJ/
kmhphMJ5BuwtFJjaLgumKSg4cCCc/3UwYV9WGq9EHF2KykCYfWmHspho5qrtM101
LF2EqVC0F1ReJIFPr3X0qfA/BRxkEnix62Ae7ukEtkFMQ9NiPIaADNdAP3D/+j7q
n+qhnWs+UgyQgKLbtWbG+9KMxcU2aXkMZXBIJp2Hbi48aY8jF/BkgNYsMZ05YbD/
AOZXYAoTZhCP38hdLrm0+yVLMA+vUjUDwzcaZn4/vJk8mgHHlfp0Y4pub3eKoQVk
IEDSLMQkV4757kaLeQ1p22pYGxo9UK9YntZuNle30ghQGPegQeA9bUyFiOct4CjU
Cni19XbpAgMBAAECggEAG1pU7qOP2qEWNx9bIzix7M+8hQ8HN3iPiXQv7XbES/G3
xk1tvoUkuyOPfuyny9qZN8NTxN89D2i9TbCDc+Hs6CoA22iUeY7QXr19uES44Y0L
d3g7OM/LnVVGi2YeD6cXDX5HzbfksT1ueL6wZC5Z9MGTTf+mKgDdbpwes1Tbl0pt
Rt3HbiRtN6cbkaozf0cnfxX2LYLJdxphxG3mTKWL4xM2ygvhbRTtlHDPsG8B/bHs
El2CkifjO4eaLxwDOAswZCx/XfBFvPtSmG51x6boL140atfkBoh6kBieZ9OjRBEW
taG+ElJ70GAKVBHty0b7KpDevUpRNZ6o28jqy67F9wKBgQD44fyN0uvmw/bX8r89
lXsKamuH0dhPFB2dveVpwbiDO6Rdp4reTjhdUf/JdIOZNqfkqey8JA0chvQ7/OJF
gbBMyDCgMVF3mVSrAuLKXya/UxEm5YCsJBNVeSZWwAOUncWN65ArkINxPo6nhEt5
qt6kC9fksi1gUPFZc2AMtFPXcwKBgQDkMv5wE3N6Q2Unox4blSoT1xzCSmnlp6OX
bzn+tV+clBRflxI76VKm91a0tJ6Ka2y8WPbFqL0l8d6GUY3Uh40yTM0TVpiYTmlG
2EUAcF9B/jROist41rQCHKfhdqpbX5YcQTiE1ZopmPoK3/nvs+rla0gXLum1Fv1r
8vYoCfeJMwKBgQDQSVhyXMW+L9xiZ64y3OnHEr8BQNY1gBE1FVpsgopnkb+B/ZhT
acT0HI7jyxXjYIFr9eXAoq8yY6L8nSvEnb+s0pEXT47td64LHHQuhylHTz54ffOM
nPhtPOGgEjws4UkW98CFJQFMAd2jRi1gGmcPhTXeGFuvUq5ZfRwyJaxRDwKBgA9l
uXFKfrIzNfIUuYVW7T3ld9VMPBT42LrxEFK1XjwsaauBgAN23NLTQZBz13azhOS4
g/4WQpz60u7xNcavVsGcGQJDB4zPTZ8wHIfJDURgqJrcFpqSshaqZFF8NkZwDqrd
Y7jiyMIhxk1Ri4W2+BR+xqB5098aLANKo31UHtWtAoGAGHh6Zc5qAFSPap235hRR
/xYkHwAXmenQw9Wjm3AUkqV26dql3XdUetcPuzwCqyboqNpMGrLW5pPRkF6E3osr
6hfQ2SyC9KxuzpwHv17FNhUtkQI2sI1pKbx9+VG9n+znUEGJpo0yXD95SKJFcitE
bOE0gQzJ6bBfM15n0xaidbU=
-----END PRIVATE KEY-----";

    const DUMMY_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3drYbtHpiwwif5JoaYTC
eQbsLRSY2i4LpikoOHAgnP91MGFfVhqvRBxdispAmH1ph7KYaOaq7TNdNSxdhKlQ
tBdUXiSBT6919KnwPwUcZBJ4setgHu7pBLZBTEPTYjyGgAzXQD9w//o+6p/qoZ1r
PlIMkICi27VmxvvSjMXFNml5DGVwSCadh24uPGmPIxfwZIDWLDGdOWGw/wDmV2AK
E2YQj9/IXS65tPslSzAPr1I1A8M3GmZ+P7yZPJoBx5X6dGOKbm93iqEFZCBA0izE
JFeO+e5Gi3kNadtqWBsaPVCvWJ7WbjZXt9IIUBj3oEHgPW1MhYjnLeAo1Ap4tfV2
6QIDAQAB
-----END PUBLIC KEY-----";

    // Dummy Claims
    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    #[test]
    fn test_generate_access_token() {
        let algo = JwtAlgorithm::RS256 {
            access_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
            access_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
            refresh_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
            refresh_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
        };
        let jwt_keys = JwtKeys::from_algorithm(algo).expect("Failed to create JwtKeys");

        let kid = "some-key-id";
        let user_id = "user123";
        let expires_in = 3600;
        let extra = None;

        let token = jwt_keys.generate_access_token(kid, user_id, expires_in, extra).expect("Failed to generate token");

        assert!(!token.is_empty(), "Token should not be empty");
    }

    #[test]
    fn test_generate_refresh_token() {
        let algo = JwtAlgorithm::RS256 {
            access_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
            access_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
            refresh_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
            refresh_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
        };
        let jwt_keys = JwtKeys::from_algorithm(algo).expect("Failed to create JwtKeys");

        let kid = "some-key-id";
        let user_id = "user123";
        let expires_in = 3600;
        let extra = None;

        let token = jwt_keys.generate_refresh_token(kid, user_id, expires_in, extra).expect("Failed to generate token");

        assert!(!token.is_empty(), "Token should not be empty");
    }

    #[test]
    fn test_decode_token() {
        let algo = JwtAlgorithm::RS256 {
            access_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
            access_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
            refresh_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
            refresh_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
        };
        let jwt_keys = JwtKeys::from_algorithm(algo).expect("Failed to create JwtKeys");

        let kid = "some-key-id";
        let user_id = "user123";
        let expires_in = 3600;
        let extra = None;

        let token = jwt_keys.generate_access_token(kid, user_id, expires_in, extra).expect("Failed to generate token");

        let decoded = jwt_keys.decode_token(&token, "access").expect("Failed to decode token");

        assert_eq!(decoded.claims.sub, user_id, "User ID should match");
    }

    #[test]
    fn test_token_expiration() {

        use std::{thread, time::Duration};
        let algo = JwtAlgorithm::RS256 {
            access_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
            access_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
            refresh_private: DUMMY_PRIVATE_KEY.as_bytes().to_vec(),
            refresh_public: DUMMY_PUBLIC_KEY.as_bytes().to_vec(),
        };
        let jwt_keys = JwtKeys::from_algorithm(algo).expect("Failed to create JwtKeys");

        let kid = "some-key-id";
        let user_id = "user123";
        let expires_in = 1;
        let extra = None;

        let token = jwt_keys.generate_access_token(kid, user_id, expires_in, extra).expect("Failed to generate token");

        thread::sleep(Duration::from_secs(2));

        let result = jwt_keys.decode_token(&token, "access");

        eprintln!("{:?}", result);
        assert!(result.is_err(), "Token should have expired");
        
    }
}
