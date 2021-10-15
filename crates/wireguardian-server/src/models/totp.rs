//! Time-Based One Time Password Database Model

use crate::{models::User, otp};
use color_eyre::eyre;
use sqlx::sqlite::SqlitePool;
use std::convert::TryInto;

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct TotpParams {
    key: Vec<u8>,
    step: i64,
    base: i64,
    digits: u32,
}

impl TotpParams {
    /// Generates a set of TOTP parameters with a random key
    ///
    /// Defaults:
    /// - step: `30 seconds`
    /// - base: `0` (Unix Epoch)
    /// - digits: `6`
    pub fn generate() -> Self {
        use rand::RngCore;

        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; 32];
        rng.fill_bytes(&mut key);

        Self {
            key,
            step: 30,
            base: 0,
            digits: 6,
        }
    }

    /// Returns a TOTP URL that can be embedded in a qrcode
    ///
    /// # Arguments
    /// * `label` - Label to embed in the uri
    pub fn uri(&self, label: &str) -> String {
        let key = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &self.key);
        format!(
            "otpauth://totp/{label}?secret={secret}&algorithm=SHA1&digits={digits}&period={step}",
            label = label,
            secret = key,
            digits = self.digits,
            step = self.step
        )
    }

    /// Fetches the TOTP parameters for a user from the backend
    ///
    /// # Arguments
    /// * `db` - Connection to the backend
    /// * `user` - User to fetch the creds for
    pub async fn fetch_by_user(db: &SqlitePool, user: &User) -> eyre::Result<Self> {
        let user_id = user.id();
        let params = sqlx::query!(
            "SELECT key, step, base, digits FROM totp WHERE user_id = ?",
            user_id
        )
        .fetch_one(db)
        .await?;

        let key = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &params.key)
            .ok_or(eyre::eyre!("failed to base32 decode totp key"))?;
        let digits: u32 = params.digits.try_into()?;

        Ok(Self {
            key,
            step: params.step,
            base: params.base,
            digits,
        })
    }

    /// Saves this TOTP for a given user in the backend
    ///
    /// # Arguments
    /// * `db` - Conenction to the backend
    /// * `user` - User for this TOTP
    pub async fn save(&self, db: &SqlitePool, user: &User) -> eyre::Result<()> {
        let user_id = user.id();
        let key = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &self.key);
        sqlx::query!(
            "INSERT INTO totp (user_id, key, step, base, digits) VALUES (?, ?, ?, ?, ?)",
            user_id,
            key,
            self.step,
            self.base,
            self.digits
        )
        .execute(db)
        .await?;

        Ok(())
    }

    /// Generates the current totp code for these paramters
    pub fn code(&self) -> eyre::Result<u32> {
        otp::totp(&self.key, self.step, self.base, self.digits)
    }

    /// Validates a code against these parameters
    ///
    /// # Arguments
    /// * `code` - TOTP code provided by user
    pub fn validate(&self, code: u32) -> eyre::Result<()> {
        let generated = self.code()?;

        if generated == code {
            Ok(())
        } else {
            eyre::bail!("totp code mismatch")
        }
    }
}
