use crate::model::Claims;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, DecodingKey, EncodingKey, Header, Validation, TokenData, errors::Result};
use serde_json::Value;
use std::collections::HashMap;

const ACCESS_EXP_MINUTES: i64 = 15;
const REFRESH_EXP_DAYS: i64 = 7;

pub struct JwtKeys {
    pub access_secret: String,
    pub refresh_secret: String,
}

impl JwtKeys {
    pub fn new(access_secret: &str, refresh_secret: &str) -> Self {
        Self {
            access_secret: access_secret.to_owned(),
            refresh_secret: refresh_secret.to_owned(),
        }
    }

    pub fn generate_access_token(
        &self,
        user_id: &str,
        extra_claims: Option<HashMap<String, Value>>,
    ) -> Result<String> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::minutes(ACCESS_EXP_MINUTES))
            .unwrap()
            .timestamp() as usize;

        let claims = Claims {
            sub: user_id.to_owned(),
            exp: expiration,
            extra: extra_claims.unwrap_or_default(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.access_secret.as_bytes()),
        )
    }

    pub fn generate_refresh_token(
        &self,
        user_id: &str,
        extra_claims: Option<HashMap<String, Value>>,
    ) -> Result<String> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::days(REFRESH_EXP_DAYS))
            .unwrap()
            .timestamp() as usize;

        let claims = Claims {
            sub: user_id.to_owned(),
            exp: expiration,
            extra: extra_claims.unwrap_or_default(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.refresh_secret.as_bytes()),
        )
    }

    pub fn decode_token(&self, token: &str, token_type: &str) -> Result<TokenData<Claims>> {
        let secret = match token_type {
            "access" => &self.access_secret,
            "refresh" => &self.refresh_secret,
            _ => return Err(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)),
        };

        decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
    }
}
