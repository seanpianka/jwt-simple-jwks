pub use error::Error;
pub use keyset::{JwtKey, KeyStore};

pub mod error;
pub mod keyset;

///JWKS client library [![Build Status](https://travis-ci.com/jfbilodeau/jwks-client.svg?branch=master)](https://travis-ci.com/jfbilodeau/jwks-client) [![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
///===
///JWKS-Client is a library written in Rust to decode and validate JWT tokens using a JSON Web Key Store.
///
///I created this library specifically to decode GCP/Firebase JWT but should be useable with little to no modification. Contact me to propose support for different JWKS key store.
///
///TODO:
///* More documentation :P
///* Extract expiration time of keys from HTTP request
///* Automatically refresh keys in background
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jwt_simple::prelude::*;
    use serde::{Deserialize, Serialize};

    use crate::keyset::{JwtKey, KeyStore};

    // const PRIVATE_KEY: &str = include_str!("../test/private.pem");
    const TIME_NBF: u64 = 300;
    const TIME_SAFE: u64 = 400;
    const TIME_EXP: u64 = 500;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct CustomClaims {
        auth_time: i64,
        name: String,
        user_id: String,
        email: String,
    }

    pub const KEY_URL: &str = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/0.1.8/test/test-jwks.json";
    pub const E: &str = "AQAB";
    pub const N: &str = "t5N44H1mpb5Wlx_0e7CdoKTY8xt-3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn__Zaxx9dnzHbzGCul5W0RLfd3oB3PESwsrQh-oiXVEPTYhvUPQkX0vBfCXJtg_zY2mY1DxKOIiXnZ8PaK_7Sx0aMmvR__0Yy2a5dIAWCmjPsxn-PcGZOkVUm-D5bH1-ZStcA_68r4ZSPix7Szhgl1RoHb9Q6JSekyZqM0Qfwhgb7srZVXC_9_m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T-Ai-4_5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV1w";
    pub const N_INVALID: &str = "xt5N44H1mpb5Wlx_0e7CdoKTY8xt-3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn__Zaxx9dnzHbzGCul5W0RLfd3oB3PESwsrQh-oiXVEPTYhvUPQkX0vBfCXJtg_zY2mY1DxKOIiXnZ8PaK_7Sx0aMmvR__0Yy2a5dIAWCmjPsxn-PcGZOkVUm-D5bH1-ZStcA_68r4ZSPix7Szhgl1RoHb9Q6JSekyZqM0Qfwhgb7srZVXC_9_m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T-Ai-4_5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV1w==";
    pub const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";
    pub const TOKEN_INV_CERT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.XXXeTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    #[derive(Debug, Serialize, Deserialize)]
    pub struct TestPayload {
        pub iss: String,
        pub name: String,
        pub email: String,
    }

    #[test_log::test]
    fn should() {
        #[derive(Serialize, Deserialize, Debug)]
        pub struct CustomClaims {
            auth_time: i64,
            name: String,
            user_id: String,
            email: String,
        }
        let key = RS256PublicKey::from_pem(
            r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt5N44H1mpb5Wlx/0e7Cd
oKTY8xt+3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn//Zaxx9dnzHbzGCul5W0RLf
d3oB3PESwsrQh+oiXVEPTYhvUPQkX0vBfCXJtg/zY2mY1DxKOIiXnZ8PaK/7Sx0a
MmvR//0Yy2a5dIAWCmjPsxn+PcGZOkVUm+D5bH1+ZStcA/68r4ZSPix7Szhgl1Ro
Hb9Q6JSekyZqM0Qfwhgb7srZVXC/9/m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T+
Ai+4/5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV
1wIDAQAB
-----END PUBLIC KEY-----"#,
        )
        .unwrap();
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";
        let verification = VerificationOptions {
            allowed_issuers: Some(HashSet::from(["https://chronogears.com/test".to_owned()])),
            artificial_time: Some(UnixTimeStamp::from_secs(TIME_SAFE)),
            time_tolerance: Some(coarsetime::Duration::from_secs(100)),
            ..Default::default()
        };
        key.verify_token::<CustomClaims>(jwt, Some(verification)).unwrap();
    }

    #[test_log::test]
    fn test_new_with_url() {
        let key_set = tokio_test::block_on(KeyStore::new_from(KEY_URL.to_owned())).unwrap();

        assert_eq!(KEY_URL, key_set.key_set_url());
    }

    #[test_log::test]
    fn test_refresh_keys() {
        let key_set = tokio_test::block_on(KeyStore::new_from(KEY_URL.to_owned())).unwrap();
        tracing::debug!("key_set: {:#?}", key_set);

        assert_eq!(KEY_URL, key_set.key_set_url());
        assert!(key_set.keys_len() > 0);

        assert!(key_set.key_by_id("1").is_some());
        assert!(key_set.key_by_id("2").is_none());

        let validation = VerificationOptions {
            allowed_issuers: Some(HashSet::from(["https://chronogears.com/test".to_owned()])),
            artificial_time: Some(UnixTimeStamp::from_secs(TIME_SAFE)),
            time_tolerance: Some(coarsetime::Duration::from_secs(0)),
            ..Default::default()
        };

        let result = key_set.verify::<CustomClaims>(TOKEN, Some(validation));

        let jwt = result.unwrap();

        assert_eq!("https://chronogears.com/test", jwt.issuer.unwrap());
        assert_eq!("Ada Lovelace", jwt.custom.name);
        assert_eq!("alovelace@chronogears.com", jwt.custom.email);
    }

    #[test_log::test]
    fn test_add_key() {
        let key = JwtKey::new_rsa256("1", N, E);

        let mut key_set = KeyStore::new();

        assert_eq!(0usize, key_set.keys_len());

        key_set.add_key(key);

        assert_eq!(1usize, key_set.keys_len());

        let result = key_set.key_by_id("1");

        assert!(result.is_some());
    }

    #[test_log::test]
    fn test_get_key() {
        let key = JwtKey::new_rsa256("1", N, E);

        let mut key_set = KeyStore::new();

        assert_eq!(0usize, key_set.keys_len());

        key_set.add_key(key);

        assert_eq!(1usize, key_set.keys_len());

        let result = key_set.key_by_id("1");

        assert!(result.is_some());

        let result = key_set.key_by_id("2");

        assert!(result.is_none());
    }

    #[test_log::test]
    fn test_verify() {
        let key = JwtKey::new_rsa256("1", N, E);

        let mut key_set = KeyStore::new();

        key_set.add_key(key);

        let validation = VerificationOptions {
            allowed_issuers: Some(HashSet::from(["https://chronogears.com/test".to_owned()])),
            artificial_time: Some(UnixTimeStamp::from_secs(TIME_SAFE)),
            time_tolerance: Some(coarsetime::Duration::from_secs(100)),
            ..Default::default()
        };

        let jwt = key_set.verify::<CustomClaims>(TOKEN, Some(validation)).unwrap();

        assert_eq!("https://chronogears.com/test", jwt.issuer.unwrap());
        assert_eq!("Ada Lovelace", jwt.custom.name);
        assert_eq!("alovelace@chronogears.com", jwt.custom.email);

        let validation = VerificationOptions {
            allowed_issuers: Some(HashSet::from(["https://chronogears.com/test".to_owned()])),
            artificial_time: Some(UnixTimeStamp::from_secs(TIME_NBF - 1)),
            time_tolerance: Some(coarsetime::Duration::from_secs(0)),
            ..Default::default()
        };
        let result = key_set.verify::<CustomClaims>(TOKEN, Some(validation)); // early

        assert!(result.is_err(), "{:?}", result);

        let validation = VerificationOptions {
            allowed_issuers: Some(HashSet::from(["https://chronogears.com/test".to_owned()])),
            artificial_time: Some(UnixTimeStamp::from_secs(TIME_EXP + 1)),
            time_tolerance: Some(coarsetime::Duration::from_secs(0)),
            ..Default::default()
        };
        let result = key_set.verify::<CustomClaims>(TOKEN, Some(validation)); // late

        assert!(result.is_err());
    }

    #[test_log::test]
    fn test_verify_invalid_certificate() {
        let key = JwtKey::new_rsa256("1", N_INVALID, E);

        let mut key_set = KeyStore::new();

        key_set.add_key(key);

        let validation = VerificationOptions {
            allowed_issuers: Some(HashSet::from(["https://chronogears.com/test".to_owned()])),
            artificial_time: Some(UnixTimeStamp::from_ticks(TIME_SAFE)),
            time_tolerance: Some(coarsetime::Duration::from_secs(0)),
            ..Default::default()
        };

        let result = key_set.verify::<CustomClaims>(TOKEN, Some(validation));

        assert!(result.is_err());
    }

    #[test_log::test]
    fn test_verify_invalid_signature() {
        let key = JwtKey::new_rsa256("1", N, E);

        let mut key_set = KeyStore::new();

        key_set.add_key(key);

        let validation = VerificationOptions {
            allowed_issuers: Some(HashSet::from(["https://chronogears.com/test".to_owned()])),
            time_tolerance: Some(coarsetime::Duration::from_secs(0)),
            ..Default::default()
        };

        let result = key_set.verify::<CustomClaims>(TOKEN_INV_CERT, Some(validation));

        assert!(result.is_err());
    }

    #[test_log::test]
    fn test_keys_expired() {
        let key_store = KeyStore::new();

        assert_eq!(None, key_store.last_load_time());
        assert_eq!(None, key_store.keys_expired());

        let key_store = tokio_test::block_on(KeyStore::new_from(KEY_URL.to_owned())).unwrap();

        assert!(key_store.last_load_time().is_some());
        assert!(key_store.keys_expired().is_some());
        assert!(!key_store.keys_expired().unwrap());
    }

    #[test_log::test]
    fn test_should_refresh() {
        let mut key_store = KeyStore::new();

        assert_eq!(0.5, key_store.refresh_interval());
        assert_eq!(None, key_store.expire_time());
        assert_eq!(None, key_store.keys_expired());
        assert_eq!(None, key_store.last_load_time());
        assert_eq!(None, key_store.should_refresh());

        key_store.set_refresh_interval(0.75);
        assert_eq!(0.75, key_store.refresh_interval());

        key_store.set_refresh_interval(0.5);

        tokio_test::block_on(key_store.load_keys_from(KEY_URL.to_owned())).unwrap();

        assert_eq!(0.5, key_store.refresh_interval());
        assert_ne!(None, key_store.expire_time());
        assert_ne!(None, key_store.keys_expired());
        assert_ne!(None, key_store.last_load_time());
        assert_eq!(Some(false), key_store.should_refresh());

        let key_duration = key_store.expire_time().unwrap().duration_since(key_store.load_time().unwrap());
        let key_duration = key_duration.unwrap();

        let refresh_time = key_store.load_time().unwrap() + (key_duration / 2);

        assert_eq!(Some(refresh_time), key_store.refresh_time());

        // Boundary test
        let just_before = refresh_time - Duration::new(1, 0);
        assert_eq!(Some(false), key_store.should_refresh_time(just_before));

        let just_after = refresh_time + Duration::new(1, 0);
        assert_eq!(Some(true), key_store.should_refresh_time(just_after));
    }
}
