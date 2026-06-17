use std::time::{Duration, SystemTime};
use std::{convert::TryFrom, convert::TryInto};

use base64::Engine;
use jwt_simple::prelude::*;
use regex::Regex;
use reqwest::Response;
use serde::{de::DeserializeOwned, Deserialize};

use crate::error::*;

#[derive(Debug, Deserialize)]
pub struct JWK {
    pub alg: Option<String>,
    pub kid: String,
    pub kty: String,
    pub e: Option<String>,
    pub n: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RSAPublicKeyInputs {
    n: String,
    e: String,
}

impl RSAPublicKeyInputs {
    pub fn new(n: String, e: String) -> RSAPublicKeyInputs {
        RSAPublicKeyInputs { n, e }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtKey {
    pub kty: String,
    pub alg: Option<String>,
    pub kid: String,
    pub kind: JwtKeyKind,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum JwtKeyKind {
    RSA(RSAPublicKeyInputs),
    UnsupportedKty(String),
}

impl JwtKey {
    pub fn new(kid: &str, alg: String, key: RSAPublicKeyInputs) -> JwtKey {
        JwtKey {
            kty: "JTW".to_string(),
            alg: Some(alg),
            kid: kid.to_owned(),
            kind: JwtKeyKind::RSA(key),
        }
    }

    pub fn new_rsa256(kid: &str, n: &str, e: &str) -> JwtKey {
        JwtKey {
            kty: "JTW".to_string(),
            alg: Some(RS256PublicKey::jwt_alg_name().to_string()),
            kid: kid.to_owned(),
            kind: JwtKeyKind::RSA(RSAPublicKeyInputs::new(n.to_owned(), e.to_owned())),
        }
    }

    pub fn decoding_key(&self) -> Result<RSAPublicKeyInputs, Error> {
        match &self.kind {
            JwtKeyKind::RSA(key_inputs) => Ok(key_inputs.clone()),
            JwtKeyKind::UnsupportedKty(kty) => {
                tracing::debug!("Unsupported key type: {}", kty);
                Err(err("Unsupported key type", Type::Key))
            }
        }
    }
}

impl TryFrom<JWK> for JwtKey {
    type Error = Error;

    fn try_from(JWK { kid, alg, kty, n, e }: JWK) -> Result<Self, Error> {
        let kind = match (kty.as_ref(), n, e) {
            ("RSA", Some(n), Some(e)) => JwtKeyKind::RSA(RSAPublicKeyInputs::new(n, e)),
            ("RSA", _, _) => return Err(err("RSA key missing parameters", Type::Certificate)),
            (_, _, _) => JwtKeyKind::UnsupportedKty(kty.clone()),
        };
        let alg = alg.unwrap_or("RS256".to_owned());
        Ok(JwtKey { kty, kid, alg: Some(alg), kind })
    }
}

#[derive(Debug)]
pub struct KeyStore {
    key_url: String,
    keys: Vec<JwtKey>,
    refresh_interval: f64,
    load_time: Option<SystemTime>,
    expire_time: Option<SystemTime>,
    refresh_time: Option<SystemTime>,
}

impl KeyStore {
    pub fn new() -> KeyStore {
        KeyStore {
            key_url: "".to_owned(),
            keys: Vec::new(),
            refresh_interval: 0.5,
            load_time: None,
            expire_time: None,
            refresh_time: None,
        }
    }

    #[tracing::instrument]
    pub async fn new_from(jkws_url: String) -> Result<KeyStore, Error> {
        let mut key_store = KeyStore::new();

        key_store.key_url = jkws_url;

        key_store.load_keys().await?;

        Ok(key_store)
    }

    #[tracing::instrument(skip(self))]
    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    pub fn key_set_url(&self) -> &str {
        &self.key_url
    }

    #[tracing::instrument(skip(self))]
    pub async fn load_keys_from(&mut self, url: String) -> Result<(), Error> {
        self.key_url = url;

        self.load_keys().await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn load_keys(&mut self) -> Result<(), Error> {
        #[derive(Deserialize)]
        pub struct JwtKeys {
            pub keys: Vec<JWK>,
        }

        let mut response = reqwest::get(&self.key_url).await.map_err(|_| err_con("Could not download JWKS"))?;
        tracing::debug!("Response: {:?}", response);

        let load_time = SystemTime::now();
        self.load_time = Some(load_time);

        let result = KeyStore::cache_max_age(&mut response);

        if let Ok(value) = result {
            let expire = load_time + Duration::new(value, 0);
            self.expire_time = Some(expire);
            let refresh_time = (value as f64 * self.refresh_interval) as u64;
            let refresh = load_time + Duration::new(refresh_time, 0);
            self.refresh_time = Some(refresh);
        }

        let jwks = response.json::<JwtKeys>().await.map_err(|_| err_int("Failed to parse keys"))?;

        for jwk in jwks.keys {
            self.add_key(jwk.try_into()?);
        }

        Ok(())
    }

    #[tracing::instrument]
    fn cache_max_age(response: &mut Response) -> Result<u64, ()> {
        let header = response.headers().get("cache-control").ok_or(())?;

        let header_text = header.to_str().map_err(|_| ())?;

        let re = Regex::new("max-age\\s*=\\s*(\\d+)").map_err(|_| ())?;

        let captures = re.captures(header_text).ok_or(())?;

        let capture = captures.get(1).ok_or(())?;

        let text = capture.as_str();

        let value = text.parse::<u64>().map_err(|_| ())?;

        Ok(value)
    }

    /// Fetch a key by key id (KID)
    #[tracing::instrument(skip(self))]
    pub fn key_by_id(&self, kid: &str) -> Option<&JwtKey> {
        self.keys.iter().find(|key| key.kid == kid)
    }

    /// Number of keys in keystore
    pub fn keys_len(&self) -> usize {
        self.keys.len()
    }

    /// Manually add a key to the keystore
    #[tracing::instrument(skip(self))]
    pub fn add_key(&mut self, key: JwtKey) {
        self.keys.push(key);
    }

    /// Verify a JWT token.
    /// If the token is valid, it is returned.
    ///
    /// A token is considered valid if:
    /// * Is well-formed
    /// * Has a `kid` field that matches a public signature `kid
    /// * Signature matches public key
    /// * It is not expired
    /// * The `nbf` is not set to before now
    #[tracing::instrument(skip(self))]
    pub fn verify<CustomClaims: Serialize + DeserializeOwned>(&self, token: &str, validation: Option<VerificationOptions>) -> Result<JWTClaims<CustomClaims>, Error> {
        let header = Token::decode_metadata(token).map_err(|e| {
            tracing::debug!("failed to decode token: {}", e);
            Error {
                msg: "failed to decode token",
                typ: Type::Invalid,
            }
        })?;

        let kid = header.key_id().ok_or_else(|| err_key("No key id"))?;

        let key = self.key_by_id(kid).ok_or_else(|| err_key("JWT key does not exists"))?;

        if let Some(alg) = &key.alg {
            if alg != header.algorithm() {
                return Err(err("Token and its key have non-matching algorithms", Type::Header));
            }
        } else {
            return Err(err("Token and its key have non-matching algorithms", Type::Header));
        }
        let rs256 = RS256PublicKey::jwt_alg_name();
        let rs384 = RS384PublicKey::jwt_alg_name();
        let rs512 = RS512PublicKey::jwt_alg_name();
        let data = match &key.kind {
            JwtKeyKind::RSA(key_inputs) => {
                let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key_inputs.n.as_str()).map_err(|e| {
                    tracing::debug!("failed to decode n: {}", e);
                    Error { msg: "failed to decode n", typ: Type::Key }
                })?;
                let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key_inputs.e.as_str()).map_err(|e| {
                    tracing::debug!("failed to decode e: {}", e);
                    Error { msg: "failed to decode e", typ: Type::Key }
                })?;
                let alg = if let Some(alg) = &key.alg {
                    alg
                } else {
                    return Err(err("Token and its key have non-matching algorithms", Type::Header));
                };
                match alg {
                    _ if rs256 == alg => {
                        let public_key = RS256PublicKey::from_components(n.as_ref(), e.as_ref()).unwrap();
                        tracing::debug!("{}", public_key.to_pem().unwrap());
                        let data = public_key.verify_token::<CustomClaims>(token, validation).map_err(|e| {
                            tracing::debug!("failed to verify token: {}", e);
                            Error {
                                msg: "failed to verify token",
                                typ: Type::Signature,
                            }
                        })?;
                        Ok(data)
                    }
                    _ if rs384 == alg => {
                        let public_key = RS384PublicKey::from_components(n.as_ref(), e.as_ref()).unwrap();
                        let data = public_key.verify_token::<CustomClaims>(token, validation).map_err(|e| {
                            tracing::debug!("failed to verify token: {}", e);
                            Error {
                                msg: "failed to verify token",
                                typ: Type::Signature,
                            }
                        })?;
                        Ok(data)
                    }
                    _ if rs512 == alg => {
                        let public_key = RS512PublicKey::from_components(n.as_ref(), e.as_ref()).unwrap();
                        let data = public_key.verify_token::<CustomClaims>(token, validation).map_err(|e| {
                            tracing::debug!("failed to verify token: {}", e);
                            Error {
                                msg: "failed to verify token",
                                typ: Type::Signature,
                            }
                        })?;
                        Ok(data)
                    }
                    _ => Err(err("Unsupported algorithm", Type::Key)),
                }
            }
            JwtKeyKind::UnsupportedKty(kty) => {
                tracing::error!("Unsupported key type: {}", kty);
                Err(err("Unsupported key type", Type::Key))
            }
        }?;
        Ok(data)
    }

    /// Time at which the keys were last refreshed
    pub fn last_load_time(&self) -> Option<SystemTime> {
        self.load_time
    }

    /// True if the keys are expired and should be refreshed
    ///
    /// None if keys do not have an expiration time
    pub fn keys_expired(&self) -> Option<bool> {
        self.expire_time.map(|expire| expire <= SystemTime::now())
    }

    /// Specifies the interval (as a fraction) when the key store should refresh it's key.
    ///
    /// The default is 0.5, meaning that keys should be refreshed when we are halfway through the expiration time (similar to DHCP).
    ///
    /// This method does _not_ update the refresh time. Call `load_keys` to force an update on the refresh time property.
    pub fn set_refresh_interval(&mut self, interval: f64) {
        self.refresh_interval = interval;
    }

    /// Get the current fraction time to check for token refresh time.
    pub fn refresh_interval(&self) -> f64 {
        self.refresh_interval
    }

    /// The time at which the keys were loaded
    /// None if the keys were never loaded via `load_keys` or `load_keys_from`.
    pub fn load_time(&self) -> Option<SystemTime> {
        self.load_time
    }

    /// Get the time at which the keys are considered expired
    pub fn expire_time(&self) -> Option<SystemTime> {
        self.expire_time
    }

    /// time at which keys should be refreshed.
    pub fn refresh_time(&self) -> Option<SystemTime> {
        self.refresh_time
    }

    /// Returns `Option<true>` if keys should be refreshed based on the given `current_time`.
    ///
    /// None is returned if the key store does not have a refresh time available. For example, the
    /// `load_keys` function was not called or the HTTP server did not provide a  
    pub fn should_refresh_time(&self, current_time: SystemTime) -> Option<bool> {
        if let Some(refresh_time) = self.refresh_time {
            return Some(refresh_time <= current_time);
        }

        None
    }

    /// Returns `Option<true>` if keys should be refreshed based on the system time.
    ///
    /// None is returned if the key store does not have a refresh time available. For example, the
    /// `load_keys` function was not called or the HTTP server did not provide a  
    pub fn should_refresh(&self) -> Option<bool> {
        self.should_refresh_time(SystemTime::now())
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}
