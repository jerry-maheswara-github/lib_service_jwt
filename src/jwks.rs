use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation, TokenData};
use crate::model::Claims;
use std::error::Error;

pub fn decode_with_components(
    token: &str,
    n: &str,
    e: &str,
) -> Result<TokenData<Claims>, Box<dyn Error>> {
    let decoding_key = DecodingKey::from_rsa_components(n, e)?;

    let token_data = decode::<Claims>(
        token,
        &decoding_key,
        &Validation::new(Algorithm::RS256),
    )?;

    Ok(token_data)
}
