use chrono::{TimeDelta, Utc};
use std::sync::LazyLock;

use crate::{
    CONFIG,
    api::EmptyResult,
    auth::{decode_jwt, encode_jwt},
    db::models::UserId,
};

static JWT_2FA_AUTH_ISSUER: LazyLock<String> =
    LazyLock::new(|| format!("{}|api.2fa.authenticators", CONFIG.domain_origin()));

#[derive(Serialize, Deserialize)]
pub struct AuthenticatorClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: UserId,

    pub key: String,
    pub enabled: bool,
}

pub fn generate_token(user_id: UserId, key: String, enabled: bool) -> String {
    let time_now = Utc::now();
    let claims = AuthenticatorClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(5).unwrap()).timestamp(),
        iss: JWT_2FA_AUTH_ISSUER.to_string(),
        sub: user_id,
        key,
        enabled,
    };

    encode_jwt(&claims)
}

pub fn validate(token: &str, user_id: &UserId, key: &str, enabled: bool) -> EmptyResult {
    match decode_jwt::<AuthenticatorClaims>(token, JWT_2FA_AUTH_ISSUER.to_string()) {
        Ok(claims) => {
            if claims.sub != *user_id {
                err!("Invalid verification token: Invalid user");
            }
            if claims.key != key {
                err!("Invalid verification token: Invalid key");
            }
            if claims.enabled != enabled {
                err!("Invalid verification token: Invalid state");
            }
        }
        Err(err) => err!(format!("Failed to decode verification token: {err}")),
    }
    Ok(())
}
