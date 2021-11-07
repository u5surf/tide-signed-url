# tide-singed-url
:warning: **This is an experimental middleware now** 

Serving URL query which is encrypted expiration date for the [Tide][] server framework.

- server
```rust
#[async_std::main]
async fn main() -> tide::Result {
    let mut app = tide::new();
    app.with(tide_signed_url::SignedURLMiddleware::new("0123456701234567012345670123456701234567012345670123456701234567"));
    app.at("/").get(|_| async {
        let mut res = Response::new(StatusCode::Ok);
        res.set_body(SECRET_CONTENT.to_owned());
        Ok(res)
    });
}
```

- encrypt
```rust
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
extern crate hex;

type AesCbc = Cbc<Aes256, Pkcs7>;

fn encrypt(key: &[u8], iv: &[u8], data: &str) -> String {
    let cipher = AesCbc::new_from_slices(key, iv).unwrap();
    let ciphertext = cipher.encrypt_vec(data.as_bytes());
    let mut buffer = bytebuffer::ByteBuffer::from_bytes(iv);
    buffer.write_bytes(&ciphertext);
    base64::encode(buffer.to_bytes())
}

fn main() {
    let plaintext = "foobar";
    let key = "0123456701234567012345670123456701234567012345670123456701234567";
    let iv = "1234567890abcdef1234567890abcdef";
    let key_hex = hex::decode(key).unwrap();
    let iv_hex = hex::decode(iv).unwrap();
    let enc = encrypt(&key_hex, &iv_hex, plaintext);
    println!("expire={}", enc);
}
```

- client
```rust
async fn get_contents() {
    let req = Request::new(Method::Get, Url::parse("http://_/?expire=EjRWeJCrze8SNFZ4kKvN73luPHQR7QOv6e1l0d7DUlE=").unwrap());
    let mut res: tide::http::Response = app.respond(req).await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.body_string().await.unwrap(), SECRET_CONTENT);
}
```

## Features

- If you want to serve the contents with expiration date, it is suitable that use encrypted query string `expire=xxxx` for clients
  - Clients know the encrypted query string and if the decrypted date does not elapsed present time, they can be obtained secret contents.
  - Its cipher is only supported by AES-CBC-256.

## License

Licensed under the [MIT](LICENSE.md) 

[Tide]: https://github.com/http-rs/tide

