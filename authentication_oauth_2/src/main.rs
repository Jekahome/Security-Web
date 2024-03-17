#![allow(unused_imports)]
#[macro_use]
extern crate lazy_static;

use actix_web::{web, App, HttpServer, HttpResponse};
use oauth2::{AuthorizationCode, CsrfToken, EmptyExtraTokenFields, RedirectUrl, Scope, TokenResponse};
use oauth2::basic::{BasicClient, BasicErrorResponse};
use oauth2::reqwest::http_client;
use url::Url;
use oauth2::{
    AuthUrl,
    ClientId,
    ClientSecret,
    PkceCodeChallenge,
    TokenUrl
};
use oauth2::reqwest::async_http_client;
 
use actix_web::http::{header::{self,ContentType}};
use actix_web::guard;
use actix_web::cookie::{ Key, SameSite };
use actix_web::http::header::LOCATION;
use actix_web::error::InternalError;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_session::config::{ BrowserSession, CookieContentSecurity };
use actix_cors::Cors;
use actix_files::NamedFile;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
 
use handlebars::{Handlebars, DirectorySourceOptions};
use r2d2_sqlite::SqliteConnectionManager;
use std::collections::btree_map::BTreeMap;
use rusqlite::OpenFlags;
use derive_more::Display;
use serde_json::json;
use std::fmt::Write;

fn get_env_var(env_var_name: &str) -> Option<String> {
    lazy_static! {
        static ref CLIENT_ID: String = dotenv::var("CLIENT_ID").expect("ID must be set!");
        static ref CLIENT_SECRET: String = dotenv::var("CLIENT_SECRET").expect("Secret must be set!");
    
        static ref PROVIDER_AUTH_URL: String = dotenv::var("PROVIDER_AUTH_URL_GOOGLE").expect("PROVIDER_AUTH_URL must be set!");
        static ref PROVIDER_TOKEN_URL: String = dotenv::var("PROVIDER_TOKEN_URL_GOOGLE").expect("PROVIDER_TOKEN_URL must be set!");
      
    }
    match env_var_name{
        "CLIENT_ID" => {
          Some(CLIENT_ID.to_owned())
        },
        "CLIENT_SECRET" => {
            Some(CLIENT_SECRET.to_owned())
        },
        "PROVIDER_AUTH_URL" => {
            Some(PROVIDER_AUTH_URL.to_owned())
        },
        "PROVIDER_TOKEN_URL" => {
            Some(PROVIDER_TOKEN_URL.to_owned())
        }
        _ => None
    }
}

async fn index(hb: web::Data<Handlebars<'_>> ) -> Result<HttpResponse, ServiceError> { 
    let mut pages = BTreeMap::<&str,&str>::new();
    pages.insert("/", "Home");
    pages.insert("/login", "Login");
    let data = json!({"layout": {"title":"Example Authentication OAuth 2.0"}, "pages": pages});
    let content = hb.render(&"index", &data).unwrap();
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}
 
// Обработчик запроса на аутентификацию OAuth 2.0
async fn oauth2_login() -> HttpResponse {
    // https://habr.com/ru/articles/491116/
   
    // Создание клиента OAuth 2.0
    let client =
    BasicClient::new(
        ClientId::new(get_env_var("CLIENT_ID").unwrap()),
        Some(ClientSecret::new(get_env_var("CLIENT_SECRET").unwrap())),
        AuthUrl::new(get_env_var("PROVIDER_AUTH_URL").unwrap()).unwrap(),
        Some(TokenUrl::new(get_env_var("PROVIDER_TOKEN_URL").unwrap()).unwrap())
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new("https://7e58-2-141-18-114.ngrok-free.app".to_string()).unwrap());
    // https://52bb-2-141-18-114.ngrok-free.app => https://127.0.0.1:8050/
    // Формирование URL для редиректа пользователя на страницу аутентификации провайдера
    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization process.
    /*
    Browse to: https://accounts.google.com/o/oauth2/v2/auth?
    response_type=code&
    client_id=..sdq3h.apps.googleusercontent.com&
    state=m3qlRbS3djx-M0ZKY6VwVg&
    code_challenge=I5tm7fyL0WIILEKZHddxlcsg_8TyS0jgz9OMv7QFXnw&
    code_challenge_method=S256&
    redirect_uri=https%3A%2F%2F127.0.0.1%3A8050%2Fredirect&
    scope=openid+email
    */

    println!("Browse to: {}", auth_url);

    // Редирект пользователя на страницу аутентификации провайдера
    HttpResponse::Found()
        .append_header((actix_web::http::header::LOCATION, auth_url.to_string()))
        .finish()

    /*
    Как только пользователь будет перенаправлен на URL-адрес перенаправления, вы получите доступ к
    Код авторизации. По соображениям безопасности ваш код должен проверять, что `state`
    параметр, возвращаемый сервером, соответствует `csrf_state`.
     */
    
    /* 
    // Now you can trade it for an access token.
    let token_result = client
        .exchange_code(AuthorizationCode::new("some authorization code".to_string())) // Код авторизации, возвращенный из конечной точки авторизации.
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .unwrap();
    */
}

// Обработчик колбека после успешной аутентификации OAuth 2.0
async fn oauth2_callback(info: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    // Получение кода авторизации и состояния CSRF из запроса
    let code = AuthorizationCode::new(info.get("code").unwrap().clone());
    let state = CsrfToken::new(info.get("state").unwrap().clone());
    println!("code={:?}",code.secret());// 4/0AeaYSHAJCE3TvCAB1PHyNZ76zrTwyUJ-Ml_EprbxIIx781mC8eQgp7opGIFVRj10htkS1Q
    println!("state={:?}",state.secret());// WNFlfdJTxHxnmIWiTsxCFg
  
    HttpResponse::Ok().finish()
    /* 
    // Обмен кода авторизации на токен доступа

    curl -X POST https://oauth2.googleapis.com/token -H "Content-Type: application/x-www-form-urlencoded" \
    -d "code=....SzvqwGIkxEOvGe5fyB5kJGm7KIgs4w" \
    -d "client_id=....j03dq3h.apps.googleusercontent.com" \
    -d "client_secret=....g9ky8J0HutrZ" \
    -d "redirect_uri=https://39fc-2-141-18-114.ngrok-free.app" \
    -d "access_type=offline" \
    -d "grant_type=authorization_code" \
    -d "scope=openid+email" \
     
     Ответ:
    {
        "access_token": "...ya29.a0Ad52N38aGdbK", 
        "id_token": "...IkQ", 
        "expires_in": 3599, 
        "token_type": "Bearer", 
        "scope": "https://www.googleapis.com/auth/userinfo.profile openid https://www.googleapis.com/auth/userinfo.email", 
        "refresh_token": "...yudrm5c91E3yZAdb7ZH9lU5vlbYjCOfHe3wKvICFg"
    }

    let token_result = client.exchange_code(code)
        .request(http_client)
        .unwrap();

    match token_result {
        Ok(token) => {
            // Получение информации о пользователе с использованием токена доступа  

            https://oauth2.googleapis.com/tokeninfo?id_token=..cy5nb29nbGV1c2VNoIjoibjhg
           
            {
                "iss": "https://accounts.google.com",
                "azp": "407408718192.apps.googleusercontent.com",
                "aud": "407408718192.apps.googleusercontent.com",
                "sub": "113028773143490838285",
                "at_hash": "n8SmoJrf4A9mbE7KhUQkPQ",
                "name": "Je ka",
                "picture": "https://lh3.googleusercontent.com/a/ACg8ocKyVNSG-sL81edfTA5W_k7iYv8BpnPAbJGHaDzYk2mv5Lc=s96-c",
                "given_name": "Je",
                "family_name": "ka",
                "locale": "ru",
                "iat": "1710695546",
                "exp": "1710699146",
                "alg": "RS256",
                "kid": "09bcf8028e06537d4d3ae4d84f5c5babcf2c0f0a",
                "typ": "JWT"
            }

            let user_info = client.userinfo(&token.access_token().unwrap()).unwrap();
            // TODO: Обработка информации о пользователе

            HttpResponse::Ok().body("You are successfully logged in!")
        }
        Err(err) => {
            // Обработка ошибки
            if let Some(basic_error_response) = err.downcast_ref::<BasicErrorResponse<EmptyExtraTokenFields>>() {
                // Вывод сообщения об ошибке
                println!("OAuth2 error: {:?}", basic_error_response.error());
            }
            HttpResponse::InternalServerError().finish()
        }
    }*/
}

async fn favicon() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("authentication_api_password/static_files/favicon.ico")?)
}

/*

OAuth 2.0 Playground https://developers.google.com/oauthplayground/

open "Google OAuth2 API v2" 
*/
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    dotenv::from_filename(std::path::Path::new("authentication_oauth_2/.env")).ok();
       
    let mut hbars = Handlebars::new();
    hbars.register_templates_directory("authentication_oauth_2/templates/", DirectorySourceOptions::default()).unwrap();
     

    //let url_db = dotenv::var("DB").expect("DB must be set!");
    // connect to SQLite DB
    //let manager = SqliteConnectionManager::file(url_db).with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE);
    //let pool = db::Pool::new(manager).unwrap();

    // load TLS keys
    // Для наших тестовых целей на локальном хосте достаточно, так называемого, self-signed certificate:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout cert/key.pem -out cert/cert.pem -days 365 -subj '/CN=localhost'`
    // password: 12345
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file("authentication_oauth_2/cert/key.pem", SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file("authentication_oauth_2/cert/cert.pem").unwrap();

 
    let secret_key = Key::generate();
    //let message_store = actix_web_flash_messages::storage::CookieMessageStore::builder(secret_key.clone()).build();
 
    // TODO: промежуточное программное обеспечение вызывается в порядке, обратном регистрации!
    HttpServer::new(move || {   
         
        App::new()
            .wrap(
                actix_web::middleware::Logger::new("All headers %{AH}xi")
                .custom_request_replace("AH", |req|  {
                    println!("\n");
                    for h in req.headers(){
                        let name = h.0.as_str().to_uppercase();
                        if name == "COOKIE" {
                            println!("{name:-<width$}{value:?}",width=28,name=name, value=h.1.to_str());  
                        } 
                    } 
                    println!("\n");
                    "".to_owned()
                    }
             ))
              .wrap(
                actix_web::middleware::Logger::new("
                Peer IP address=%a
                First line of request=%r
                Response status code=%s
                Content-type=%{Content-type}i
                Set-Cookie=%{Set-Cookie}i
                \n+-+-+-+-+-+-+-++-+-+-\n") 
            )
            /*.wrap(
                // Сохранение и управление состоянием между запросами в CookieSessionStore.
                // SessionMiddleware<CookieSessionStore>
                SessionMiddleware::builder(
                    CookieSessionStore::default(), secret_key.clone()
                )
                //.cookie_name(String::from("my-kata-cookie")) // arbitrary name
                .cookie_secure(true) // true=https only
                //.session_lifecycle(BrowserSession::default()) // expire at end of session
                .session_lifecycle(actix_session::config::PersistentSession::default().session_ttl(actix_web::cookie::time::Duration::hours(1)))
                .cookie_content_security(CookieContentSecurity::Private) // encrypt
                .cookie_same_site(SameSite::Lax)
                //.cookie_same_site(SameSite::Strict) 
                .cookie_http_only(true) // disallow scripts from reading
                .build()
            )*/  
            /*.wrap(
                //Cors::permissive() // без ограничений
                 Cors::default() 
                .allowed_origin_fn(|h,r|->bool{
                    println!("----HeaderValue{:?} \n\nRequestHead={:?}\n\n",h,r);
                    true
                })
                //.allowed_origin("http://127.0.0.1:8090")
                .allowed_methods(vec!["GET", "POST", "DELETE"])
                .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                .allowed_header(header::CONTENT_TYPE)
                .max_age(3600) 
            )*/
            .app_data(web::Data::new(hbars.clone()))
            //.app_data(web::Data::new(pool.clone()))
           // .route("/", web::get().to(index))
            .route("/favicon.ico", web::get().to(favicon))
            .route("/login", web::get().to(oauth2_login))// https://127.0.0.1:8555/login
            .route("/redirect", web::get().to(oauth2_callback)) // https://127.0.0.1:8555/redirect
           
            .default_service(web::route().guard(guard::Not(guard::Get())).to(HttpResponse::MethodNotAllowed))
    })
    .workers(4) 
    .bind_openssl("127.0.0.1:8555", builder)?
    .run()
    .await
}
 

#[derive(Debug, Display)]
pub enum ServiceError {
    #[display(fmt = "Internal Server Error")]
    InternalServerError,

    #[display(fmt = "BadRequest: {}", _0)]
    BadRequest(String),

}

impl actix_web::error::ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServiceError::InternalServerError => {
                HttpResponse::InternalServerError().json("Internal Server Error, Please try later")
            }
            ServiceError::BadRequest(ref message) => HttpResponse::BadRequest().json(message),
        }
    }
    fn status_code(&self) -> actix_web::http::StatusCode {
        match *self {
            ServiceError::InternalServerError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            ServiceError::BadRequest(_) => actix_web::http::StatusCode::BAD_REQUEST,
        }
    }
}

 