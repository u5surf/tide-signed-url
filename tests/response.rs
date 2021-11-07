use tide::http::{Method, Request, StatusCode, Url};
use tide::Response;

const TEXT: &str = concat![
   "secret content"
];

#[async_std::test]
async fn response() {
    let mut app = tide::new();
    app.with(tide_signed_url::SignedURLMiddleware::new("0123456701234567012345670123456701234567012345670123456701234567"));
    app.at("/").get(|_| async {
        let mut res = Response::new(StatusCode::Ok);
        res.set_body(TEXT.to_owned());
        Ok(res)
    });

    let req = Request::new(Method::Get, Url::parse("http://_/?expire=EjRWeJCrze8SNFZ4kKvN73luPHQR7QOv6e1l0d7DUlE=").unwrap());
    let mut res: tide::http::Response = app.respond(req).await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.body_string().await.unwrap(), TEXT);
}

#[async_std::test]
async fn response_without_query() {
    let mut app = tide::new();
    app.with(tide_signed_url::SignedURLMiddleware::new("0123456701234567012345670123456701234567012345670123456701234567"));
    app.at("/").get(|_| async {
        let mut res = Response::new(StatusCode::Ok);
        res.set_body(TEXT.to_owned());
        Ok(res)
    });

    let req = Request::new(Method::Get, Url::parse("http://_/").unwrap());
    let mut res: tide::http::Response = app.respond(req).await.unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(res.body_string().await.unwrap(), "");
}
#[async_std::test]
async fn response_expired() {
    let mut app = tide::new();
    app.with(tide_signed_url::SignedURLMiddleware::new("0123456701234567012345670123456701234567012345670123456701234567"));
    app.at("/").get(|_| async {
        let mut res = Response::new(StatusCode::Ok);
        res.set_body(TEXT.to_owned());
        Ok(res)
    });

    let req = Request::new(Method::Get, Url::parse("http://_/?expire=EjRWeJCrze8SNFZ4kKvN71vxFu11f5XQS8jGuvylrZE=").unwrap());
    let mut res: tide::http::Response = app.respond(req).await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.body_string().await.unwrap(), "");
}

#[async_std::test]
async fn response_invalid_expire() {
    let mut app = tide::new();
    app.with(tide_signed_url::SignedURLMiddleware::new("0123456701234567012345670123456701234567012345670123456701234567"));
    app.at("/").get(|_| async {
        let mut res = Response::new(StatusCode::Ok);
        res.set_body(TEXT.to_owned());
        Ok(res)
    });

    let req = Request::new(Method::Get, Url::parse("http://_/?expire=EjRWeJCrze8SNFZ4kKvN7xPBPhOrKDQ7/9mqcHT2XBo=").unwrap());
    let mut res: tide::http::Response = app.respond(req).await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.body_string().await.unwrap(), "");
}

#[async_std::test]
async fn response_decrypt_fail() {
    let mut app = tide::new();
    app.with(tide_signed_url::SignedURLMiddleware::new("0123456701234567012345670123456701234567012345670123456701234567"));
    app.at("/").get(|_| async {
        let mut res = Response::new(StatusCode::Ok);
        res.set_body(TEXT.to_owned());
        Ok(res)
    });

    let req = Request::new(Method::Get, Url::parse("http://_/?expire=EjRWeJCrze8SNFZ4kKvN7xPBPhOrKDQ7").unwrap());
    let mut res: tide::http::Response = app.respond(req).await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.body_string().await.unwrap(), "");
}
