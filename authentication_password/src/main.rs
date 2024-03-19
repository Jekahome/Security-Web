#![allow(unused_imports)]
 
#[macro_use]
extern crate lazy_static;

use actix_web::{web, App, HttpResponse, HttpServer};
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
use actix_web_prom::{PrometheusMetricsBuilder};
use actix_web_flash_messages::FlashMessage;
use actix_web_flash_messages::FlashMessagesFramework;
use actix_web_flash_messages::IncomingFlashMessages;
use handlebars::{Handlebars, DirectorySourceOptions};
use r2d2_sqlite::SqliteConnectionManager;
use std::collections::btree_map::BTreeMap;
use rusqlite::OpenFlags;
use derive_more::Display;
use serde_json::json;
use std::fmt::Write;

use regex::Regex;

mod db;
use db::Pool;
mod session_state;
use session_state::TypedSession;

fn is_valid_user_input(value: &str) -> bool{
    lazy_static! {
        static ref REGEX_VALIDATION: Regex = Regex::new(r"^[\w .,!?]{4,30}$").unwrap();
    }
    REGEX_VALIDATION.is_match(value)
}
 
async fn index(hb: web::Data<Handlebars<'_>>, session: TypedSession ) -> Result<HttpResponse, ServiceError> { 
    let mut pages = BTreeMap::<&str,&str>::new();
    pages.insert("/", "Home");
    if let Ok(Some(_user_id)) = session.get_user_id() {
        pages.insert("/user/dashboard", "User Dashboard");
        pages.insert("/user/password", "Change password");       
    }else{
        pages.insert("/login", "Login");
        pages.insert("/registration", "Registration");
    }
     
    let data = json!({"layout": {"title":"Example HTTP authentication"}, "pages": pages});
    let content = hb.render(&"index", &data).unwrap();
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}

// После редиректа IncomingFlashMessages будет уже с данными которые были заполненны с помощью FlashMessage
async fn registration_form(hb: web::Data<Handlebars<'_>>, flash_messages: IncomingFlashMessages) -> Result<HttpResponse, ServiceError> { 
    let mut msg_html = String::new();
    for m in flash_messages.iter() {
        if m.level() == actix_web_flash_messages::Level::Info{
            writeln!(msg_html, "<div class=\"alert alert-info\" role=\"alert\"><i>{}</i></div>", m.content()).unwrap();
        }else{
            writeln!(msg_html, "<div class=\"alert alert-danger\" role=\"alert\"><i>{}</i></div>", m.content()).unwrap();
        }
    }

    let mut pages = BTreeMap::<&str,&str>::new();
    pages.insert("/", "Home");
    pages.insert("/login", "Login");

    let data = json!({"layout": {"title":"Registration"}, "pages": pages, "msg_html":msg_html});
    let content = hb.render(&"registration", &data).unwrap();
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}

/*
`curl --insecure --cacert cert/cert.pem \
-d '{ "username": "bocksdin","password":"supersecret"}' \
-H "Content-Type: application/json" \
-X POST https://127.0.0.1:8060/registration`
*/
// Ожидает данные от формы в формате: application/x-www-form-urlencoded
// Необходим редирект при успещной обработке запроса на другую страницу 
// чтобы избежать повторной отправки при обновлении страницы
async fn registration(db: web::Data<Pool>, body: web::Form<db::InputUser>) -> Result<HttpResponse, ServiceError> { 
    let mut user: db::InputUser = body.into_inner();
    if !is_valid_user_input(&user.username) || !is_valid_user_input(&user.password){
        FlashMessage::error("Your data is not correct").send();
        return Ok(HttpResponse::SeeOther().insert_header((LOCATION, "/registration")).finish())
    }
    user.password = compute_password_hash(user.password);
    let _id = db::create_user(&db, user)
        .await
        .map_err(|_e| ServiceError::InternalServerError)?;
    FlashMessage::info("You have successfully registered").send();
    Ok(HttpResponse::SeeOther().insert_header((LOCATION, "/login")).finish())
}
 
async fn login_form(hb: web::Data<Handlebars<'_>>, flash_messages: IncomingFlashMessages) -> Result<HttpResponse, ServiceError> { 
    let mut msg_html = String::new();
    for m in flash_messages.iter() {
        if m.level() == actix_web_flash_messages::Level::Info{
            writeln!(msg_html, "<div class=\"alert alert-info\" role=\"alert\"><i>{}</i></div>", m.content()).unwrap();
        }else{
            writeln!(msg_html, "<div class=\"alert alert-danger\" role=\"alert\"><i>{}</i></div>", m.content()).unwrap();
        }
    }
    let mut pages = BTreeMap::<&str,&str>::new();
    pages.insert("/", "Home");

    let data = json!({"layout": {"title":"Login"}, "pages": pages, "msg_html":msg_html});
    let content = hb.render(&"login", &data).unwrap();
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}



#[derive(derive_more::Display)]
pub enum LoginError {
    AuthError(AuthError),
    UnexpectedError(String),
}

impl std::error::Error for LoginError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoginError::AuthError(err) => Some(err),
            LoginError::UnexpectedError(_) => None,
        }
    }
}

impl std::fmt::Debug for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

pub fn error_chain_fmt(e: &impl std::error::Error,f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(f, "{}\n", e)?;
    let mut current = e.source();
    while let Some(cause) = current {
        writeln!(f, "Caused by:\n\t{}", cause)?;
        current = cause.source();
    }
    Ok(())
}


/*
`curl --insecure --cacert cert/cert.pem \
-d '{ "username": "bocksdin","password":"supersecret"}' \
-H "Content-Type: application/json" \
-X POST https://127.0.0.1:8060/login`
*/
// Ожидает данные от формы в формате: application/json
// Без редиректа так как ожидается AJAX запрос
async fn login( db: web::Data<Pool>, body: web::Json<db::InputUser>, session: TypedSession) -> Result<HttpResponse, actix_web::error::InternalError<LoginError>> { 
    let credentials = Credentials::new(body.username.clone(), body.password.clone());  
    match validate_credentials(credentials, &db).await {
        Ok(user_id) => {
            // возобновляем сеанс после вызова входа в систему для предотвращения атак фиксации сеанса
            session.renew();
             
            session.insert_user_id(user_id)
            .map_err(|e|{
               actix_web::error::InternalError::from_response(LoginError::UnexpectedError(e.to_string()), HttpResponse::BadRequest().finish())
            })?;

            Ok(HttpResponse::Ok().finish())
        },
        Err(e) => {
            //let response = HttpResponse::SeeOther().insert_header((LOCATION, "/login")).finish();
            //Err(actix_web::error::InternalError::from_response(e, response) )
            let e = match e {
                AuthError::InvalidCredentials(_) => LoginError::AuthError(e.into()),
                AuthError::UnexpectedError(_) => LoginError::UnexpectedError(e.to_string()),
            };
            Err(actix_web::error::InternalError::from_response(e, HttpResponse::BadRequest().body("Authorization failed")) )
        }
    }
}
  
pub async fn log_out(session: TypedSession ) -> Result<HttpResponse, ServiceError> {
    if session.get_user_id().map_err(|_|ServiceError::InternalServerError)?.is_none() {
        Ok(HttpResponse::SeeOther().insert_header((LOCATION, "/login")).finish())
    } else {
        session.log_out();
        FlashMessage::info("You have successfully logged out.").send();
        Ok(HttpResponse::SeeOther().insert_header((LOCATION, "/login")).finish())
    }
}

pub async fn user_dashboard(hb: web::Data<Handlebars<'_>>, session: TypedSession, pool: web::Data<Pool> ) -> Result<HttpResponse, ServiceError> {
    let username = if let Some(user_id) = session.get_user_id().map_err(|_|ServiceError::InternalServerError)? {
        db::get_user_by_id(&pool,user_id)
            .await
            .map(|u|u.username)
            .map_err(|_|ServiceError::InternalServerError)?
    } else {
        return Ok(HttpResponse::SeeOther().insert_header((LOCATION, "/login")).finish());
    };
    
    let mut pages = BTreeMap::<&str,&str>::new();
    pages.insert("/", "Home");
    let data = json!({"layout": {"title":"User dashboard"}, "pages": pages,"username":username});
    let content = hb.render(&"dashboard", &data).unwrap();
    
    Ok(HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(content))
}

pub async fn change_password_form(hb: web::Data<Handlebars<'_>>, session: TypedSession,  flash_messages: IncomingFlashMessages) -> Result<HttpResponse, ServiceError> {
    if session.get_user_id().map_err(|_|ServiceError::InternalServerError)?.is_none() {
        return Ok(HttpResponse::SeeOther().insert_header((LOCATION, "/login")).finish());
    }

    let mut msg_html = String::new();
    for m in flash_messages.iter() {
        if m.level() == actix_web_flash_messages::Level::Info{
            writeln!(msg_html, "<div class=\"alert alert-info\" role=\"alert\"><i>{}</i></div>", m.content()).unwrap();
        }else{
            writeln!(msg_html, "<div class=\"alert alert-danger\" role=\"alert\"><i>{}</i></div>", m.content()).unwrap();
        }
    }

    let mut pages = BTreeMap::<&str,&str>::new();
    pages.insert("/", "Home");
    let data = json!({"layout": {"title":"Change Password"}, "pages": pages, "msg_html":msg_html});
    let content = hb.render(&"change_password_form", &data).unwrap();
    Ok(HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(content))
}


#[derive(serde::Deserialize)]
pub struct FormDataChangePassword {
    current_password: String,
    new_password: String,
    new_password_check: String,
}
 
/*
curl --insecure --cacert cert/cert.pem \
-d "current_password=supersecret&new_password=newsupersecret&new_password_check=newsupersecret" \
-H "Content-Type: application/x-www-form-urlencoded" \
-X POST 127.0.0.1:8060/password
*/
pub async fn change_password(form: web::Form<FormDataChangePassword>, pool: web::Data<Pool>, user_id: web::ReqData<UserId>) -> Result<HttpResponse, ServiceError> {
    
    let user_id = user_id.into_inner();
    if form.new_password  != form.new_password_check {
        FlashMessage::error(
            "You entered two different new passwords - the field values must match.",
        )
        .send();
        return Ok(HttpResponse::SeeOther().insert_header((LOCATION, "/user/password")).finish());
    }
  
    let username = db::get_user_by_id(&pool,*user_id)
    .await
    .map(|u|u.username)
    .map_err(|_|ServiceError::InternalServerError)?;

    let credentials = Credentials::new(username, form.0.current_password);
     
    if let Err(_e) = validate_credentials(credentials, &pool).await {
        FlashMessage::error("The current password is incorrect.").send();
        return Ok(HttpResponse::SeeOther().insert_header((LOCATION, "/user/password")).finish());
    }
    
    let password_hash = compute_password_hash(form.0.new_password);
    
    db::change_password(&pool,*user_id, password_hash)
        .await
        .map_err(|_|ServiceError::InternalServerError)?;
    
    FlashMessage::error("Your password has been changed.").send();
    Ok(HttpResponse::SeeOther().insert_header((LOCATION, "/user/password")).finish())
}
 

use authentication::middleware::{reject_anonymous_users,UserId};
use authentication::compute_password_hash;
use authentication::{Credentials, validate_credentials, AuthError};
mod authentication{
    use super::{db, TypedSession, ServiceError};
    use actix_web::http::header::LOCATION;
    use actix_web::body::MessageBody;
    use actix_web::dev::{ServiceRequest, ServiceResponse};
    use actix_web::error::InternalError;
    use actix_web::{FromRequest, HttpMessage};
    use actix_web_lab::middleware::Next;
    use std::ops::Deref;
    use uuid::Uuid;
    use argon2::password_hash::SaltString;
    use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

    #[derive(Debug, derive_more::Display)]
    pub enum AuthError {
        InvalidCredentials(String),
        UnexpectedError(String),
    }

    impl std::error::Error for AuthError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                AuthError::InvalidCredentials(_) => None,
                AuthError::UnexpectedError(_) => None,
            }
        }
    }

    #[derive(Debug)]
    pub struct Credentials {
        // These two fields were not marked as `pub` before!
        username: String,
        password: String,
    }

    impl Credentials{
        pub fn new(username: String, password: String) -> Self{
            Self{username,password}
        }
    }

    pub async fn validate_credentials(credentials: Credentials, pool: &db::Pool) -> Result<Uuid, AuthError> { 
        let user = db::find_user(pool, credentials.username)
            .await
            .map_err(|e|AuthError::InvalidCredentials(e.to_string()))?;
        match verify_password_hash(user.password, credentials.password){
            Ok(_) =>{
                Ok(user.id)
            },
            Err(e)=>{
                Err(AuthError::InvalidCredentials(e.to_string())) 
            }
        }
    }

    pub fn compute_password_hash(password: String) -> String{
        let salt = SaltString::generate(&mut rand::thread_rng());
        // Match production parameters
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        )
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
        password_hash
    }

    fn verify_password_hash(expected_password_hash: String,password_candidate: String) -> Result<(), AuthError> {
        let expected_password_hash = PasswordHash::new(&expected_password_hash)
            .map_err(|e|AuthError::InvalidCredentials(e.to_string()))?;

        Argon2::default()
            .verify_password(
                password_candidate.as_bytes(),
                &expected_password_hash,
            )
            .map_err(|e|AuthError::InvalidCredentials(e.to_string()))
    }

    pub mod middleware{
        use super::*;
        
        #[derive(Copy, Clone, Debug)]
        pub struct UserId(Uuid);
        
        impl std::fmt::Display for UserId {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        
        impl Deref for UserId {
            type Target = Uuid;
        
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        // TODO: extensions_mut for extract request `web::ReqData<UserId>` 
        pub async fn reject_anonymous_users(
            mut req: ServiceRequest,
            next: Next<impl MessageBody>,
        ) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
            let session = {
                let (http_request, payload) = req.parts_mut();
                TypedSession::from_request(http_request, payload).await
            }?;
            
            match session.get_user_id().map_err(|_|ServiceError::InternalServerError)? {
                Some(user_id) => {
                    req.extensions_mut().insert(UserId(user_id));
                    next.call(req).await
                }
                None => {
                    let response = actix_web::HttpResponse::SeeOther().insert_header((LOCATION, "/login")).finish();
                     
                    let e = Box::new( std::io::Error::new(std::io::ErrorKind::Other, "The user has not logged in"));
                    Err(InternalError::from_response(e, response).into())
                }
            }
        }
    }

}

async fn favicon() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("authentication_password/static_files/favicon.ico")?)
}


/*

--------------------
Токены доступа обычно представляют собой недолговечные токены JWT, подписанные вашим сервером и включаются в 
каждый HTTP-запрос к вашему серверу для авторизации запроса.

Токены обновления обычно представляют собой долгоживущие непрозрачные строки, хранящиеся в вашей базе данных и 
используемые для получения нового токена доступа по истечении срока его действия.
*/
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    dotenv::from_filename(std::path::Path::new("authentication_password/.env")).ok();
     
   
    let mut hbars = Handlebars::new();
    hbars.register_templates_directory("authentication_password/templates/", DirectorySourceOptions::default()).unwrap();
     

    let url_db = dotenv::var("DB").expect("DB must be set!");
    // connect to SQLite DB
    let manager = SqliteConnectionManager::file(url_db).with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE);
    let pool = db::Pool::new(manager).unwrap();

    // load TLS keys
    // Для наших тестовых целей на локальном хосте достаточно, так называемого, self-signed certificate:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout cert/key.pem -out cert/cert.pem -days 365 -subj '/CN=localhost'`
    // password: 12345
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file("authentication_password/cert/key.pem", SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file("authentication_password/cert/cert.pem").unwrap();

 
    let secret_key = Key::generate();
    //let message_store = actix_web_flash_messages::storage::CookieMessageStore::builder(secret_key.clone()).build();
    let message_store = actix_web_flash_messages::storage::SessionMessageStore::default();
    let message_framework = FlashMessagesFramework::builder(message_store).minimum_level(actix_web_flash_messages::Level::Info).build();
   
    // TODO: промежуточное программное обеспечение вызывается в порядке, обратном регистрации!
    HttpServer::new(move || {   
        let prometheus = PrometheusMetricsBuilder::new("").endpoint("/metrics").build().unwrap();
         
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
            .wrap(message_framework.clone())
            .wrap(prometheus.clone())
            .wrap(
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
            )  
            .wrap(
                //Cors::permissive() // без ограничений
                 Cors::default() 
                /*.allowed_origin_fn(|h,r|->bool{
                    println!("----HeaderValue{:?} \n\nRequestHead={:?}\n\n",h,r);
                    true
                })*/
                //.allowed_origin("http://127.0.0.1:8090")
                .allowed_methods(vec!["GET", "POST", "DELETE"])
                .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                .allowed_header(header::CONTENT_TYPE)
                .max_age(3600) 
            )
            .wrap(
                // Добавление CSP
                actix_web::middleware::DefaultHeaders::new()
                    .add(("Content-Security-Policy", "default-src 'self' http://127.0.0.1"))
            )
            .app_data(web::Data::new(hbars.clone()))
            .app_data(web::Data::new(pool.clone()))
            .route("/", web::get().to(index))
            .route("/registration", web::get().to(registration_form))
            .route("/registration", web::post().to(registration))
            .route("/login", web::get().to(login_form))
            .route("/login", web::post().to(login))
            .service(
                web::scope("/user")
                    .wrap(actix_web_lab::middleware::from_fn(reject_anonymous_users))
                    .route("/dashboard", web::get().to(user_dashboard))
                    .route("/password", web::get().to(change_password_form))
                    .route("/password", web::post().to(change_password))
                    .route("/logout", web::post().to(log_out)),
            )
            .route("/favicon.ico", web::get().to(favicon))
            .service(
                // use https://127.0.0.1:8060/static
                actix_files::Files::new("/static", "authentication_password/static_files")
                    .show_files_listing()
                    .use_last_modified(true)
                    .prefer_utf8(true),
            )            
            .default_service(web::route().guard(guard::Not(guard::Get())).to(HttpResponse::MethodNotAllowed))
    })
    .workers(4) 
    .bind_openssl("127.0.0.1:8060", builder)?
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

 