use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use chrono::prelude::{DateTime, Utc};
use std::time::SystemTime;
use std::error::Error;
use tide::prelude::*;
use tide::{Middleware, Next, Request, Response, StatusCode};

type AesCbc = Cbc<Aes256, Pkcs7>;

/// A middleware for signed url.
///
#[derive(Clone, Debug)]
pub struct SignedURLMiddleware {
    key: Vec<u8>,
}

#[derive(Deserialize)]
struct Expire {
    expire: String,
}

/*impl Default for SignedURLMiddleware {
    fn default() -> Self {
    }
}*/

impl SignedURLMiddleware {
    /// Creates a new CompressMiddleware.
    ///
    /// Uses the default minimum body size threshold (1024 bytes).
    ///
    /// ## Example
    /// ```rust
    /// # async_std::task::block_on(async {
    /// let mut app = tide::new();
    ///
    /// app.with(tide_signed_url::SignedURLMiddleware::new("0123456701234567012345670123456701234567012345670123456701234567"));
    /// # })
    /// ```
    pub fn new(key : &str) -> Self {
        match hex::decode(key) {
            Ok(key_hex) =>  SignedURLMiddleware { key: key_hex },
            Err(err) => panic!("invalid: {:?}", err),
        }
    }
}

fn decrypt(key: &[u8], data: &str) -> Result<String, Box<dyn Error>> {
    let bytes = base64::decode(data)?;
    let cipher = AesCbc::new_from_slices(key, &bytes[0..16])?;
    Ok(String::from_utf8(cipher.decrypt_vec(&bytes[16..])?)?)
}

#[tide::utils::async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for SignedURLMiddleware {
    async fn handle(&self, req: Request<State>, next: Next<'_, State>) -> tide::Result {
        // Incoming Request data
        let q: Expire = req.query()?;
        let exp = match decrypt(&self.key, &q.expire) {
            Ok(exp) => exp,
            Err(_) => "".to_string(),
        };
        let exp = exp.parse::<i64>().unwrap_or(0);

        let now_unix: DateTime<Utc> = SystemTime::now().into();
        let now: i64 = now_unix.timestamp();

        if now.lt(&exp) {
            let res: Response = next.run(req).await;
            return Ok(res);
        }
        let res: Response = Response::new(StatusCode::Forbidden);
        Ok(res)
    }
}
