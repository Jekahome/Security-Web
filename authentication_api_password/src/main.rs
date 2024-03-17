
/// HTTP authentication.
/// https://www.youtube.com/watch?v=S1Mp3KMQ_kQ
/// 
/// Рассмотрен только механизм аутентификации по паролю Bearer, все сообщения об ошибках следует помещать в журнал,
/// а пользователю отдавать стандарное сообщение.
/// 
/// Если рассматривать не API то Нет сохранения сессии в SessionStorage и LocalStorage
/// --------------------------------------------------
/// 1.Create User
///     POST https://127.0.0.1:8070/user
/// 
///     curl --insecure -d '{ "username": "bocksdin","password":"supersecret"}' -H "Content-Type: application/json" -X POST https://127.0.0.1:8070/user 
/// 
/// --------------------------------------------------
/// 2.Basic Auth
///     GET https://127.0.0.1:8070/auth
/// 
///     (Возможно послать username и password через --user bocksdin:supersecret или через заголовок Authorization)
/// 
///     curl --insecure --user bocksdin:supersecret https://127.0.0.1:8070/auth 
/// 
///     Output:
///     "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.17itMtCzPavgIPt0OaPMPEZJiwASqDUppyY5u76GZEE"
///  
/// 
///     Или чтобы увидеть как кодируется Basic токен из username и password:
///     curl --insecure -v --user bocksdin:supersecret https://127.0.0.1:8070/auth
///     и видно в выводе 
///     authorization: Basic Ym9ja3NkaW46c3VwZXJzZWNyZXQ=
///     curl --insecure https://127.0.0.1:8070/auth -H 'Authorization: Basic Ym9ja3NkaW46c3VwZXJzZWNyZXQ=' 
/// 
///     Output:
///     "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.17itMtCzPavgIPt0OaPMPEZJiwASqDUppyY5u76GZEE"
/// 
///     Или так посмотеть Basic токен из username и password:
///     AUTH=$(echo -ne "bocksdin:supersecret" | base64 --wrap 0)
///     $AUTH
///     Ym9ja3NkaW46c3VwZXJzZWNyZXQ=
/// --------------------------------------------------
/// 3.Create article
///     POST https://127.0.0.1:8070/api/create-article
/// 
///     curl --insecure -d '{"title":"Head title","content":"Content body"}' -H "Content-Type: application/json" -X POST https://127.0.0.1:8070/api/create-article -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.17itMtCzPavgIPt0OaPMPEZJiwASqDUppyY5u76GZEE'
/// 
///     Output:
///     {
///      "id": 1,
///      "user_id": 1,
///       "title": "Head title",
///       "content": "Content body",
///       "created_at": "2024-03-13T00:27:55.230745989"
///     }
/// --------------------------------------------------
/// 4.Get user
///     GET https://127.0.0.1:8070/api/user
/// 
///     curl --insecure GET https://127.0.0.1:8070/api/user -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.17itMtCzPavgIPt0OaPMPEZJiwASqDUppyY5u76GZEE'
/// 
///     Output:
///     {"id":1,"username":"bocksdin","password":"$argon2id$v=19$m=4096,t=192,p=12$vc9efL3nvDm5ve8z3UTmVSmFLulaG4HTL5DJmitRiQs$SyBz27JnoK3PIUIOHhhx7B5aSjwTSJ/eoKHKfQxDED4","created_at":"2024-03-12T22:53:30.115501812"}
/// --------------------------------------------------
/// 5.Get users
///     GET https://127.0.0.1:8070/api/users
/// 
///     curl --insecure GET https://127.0.0.1:8070/api/users -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.17itMtCzPavgIPt0OaPMPEZJiwASqDUppyY5u76GZEE'
/// 
///     Output:
///     {"id":1,"username":"bocksdin","password":"$argon2id$v=19$m=4096,t=192,p=12$vc9efL3nvDm5ve8z3UTmVSmFLulaG4HTL5DJmitRiQs$SyBz27JnoK3PIUIOHhhx7B5aSjwTSJ/eoKHKfQxDED4","created_at":"2024-03-12T22:53:30.115501812"}
/// --------------------------------------------------
/// 6.DELETE User
///     DELETE https://127.0.0.1:8070/api/users
/// 
///     curl --insecure -X DELETE https://127.0.0.1:8070/api/users -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.17itMtCzPavgIPt0OaPMPEZJiwASqDUppyY5u76GZEE'
///   
///
/// 

#[macro_use]
extern crate lazy_static;

use actix_web::{web, App, HttpMessage, HttpResponse, HttpServer, Responder};
use actix_web::http::{self,header::{self,ContentType}};
use actix_web::guard::{self, Guard};
use actix_web::middleware::{self, Logger};
use actix_web::{get, post, delete};// макросы роутинга
use actix_cors::Cors;
use actix_files::NamedFile;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_web_prom::PrometheusMetricsBuilder;
use handlebars::{Handlebars, DirectorySourceOptions};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;
use serde::{Deserialize, Serialize};
use std::collections::btree_map::BTreeMap;
use serde_json::json;
use derive_more::Display;
use regex::Regex;

use actix_web_httpauth::{
    extractors::{
        basic::BasicAuth,
        bearer::{self,BearerAuth},
        AuthenticationError
    },
    middleware::HttpAuthentication
};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use sha2::Sha256;
use argonautica::{Hasher, Verifier};

mod db;
use db::Pool;

#[derive(Serialize, Deserialize, Clone)]
struct TokenClaims{
    id: i64
}

fn is_valid_user_input(value: &str) -> bool{
    lazy_static! {
        static ref REGEX_VALIDATION: Regex = Regex::new(r"^[\w .,!?]*$").unwrap();
    }
    REGEX_VALIDATION.is_match(value)
}

fn get_env_var(env_var_name: &str) -> Option<String> {
    lazy_static! {
        static ref HASH_SECRET: String = dotenv::var("HASH_SECRET").expect("HASH_SECRET must be set!");
        static ref JWT_SECRET: String = dotenv::var("JWT_SECRET").expect("JWT_SECRET must be set!");
    }
    match env_var_name{
        "HASH_SECRET" => {
          Some(HASH_SECRET.to_owned())
        },
        "JWT_SECRET" => {
            Some(JWT_SECRET.to_owned())
        }
        _ => None
    }
}

#[get("/")]
async fn index(hb: web::Data<Handlebars<'_>>, req_user: Option<web::ReqData<TokenClaims>>) -> Result<HttpResponse, ServiceError> { 
    let mut pages = BTreeMap::<&str,&str>::new();
    pages.insert("/", "Home");
    if req_user.is_none(){ 
       pages.insert("/auth", "HTTP Authentication. Get token");
    }else{
       pages.insert("/user", "Show user");
       pages.insert("/users", "Show users");
    }
    let data = json!({"layout": {"title":"HTTP authentication"}, "pages": pages});
    let content = hb.render(&"index", &data).unwrap();
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}

/*
`curl --insecure --cacert cert/cert.pem \
-d '{ "username": "bocksdin","password":"supersecret"}' \
-H "Content-Type: application/json" \
-X POST https://127.0.0.1:8070/user`
*/
#[post("/user")]
async fn create_user(db: web::Data<Pool>, body: web::Json<db::InputUser>) -> Result<HttpResponse, ServiceError> { 
    let mut user: db::InputUser = body.into_inner();
    if !is_valid_user_input(&user.username) || !is_valid_user_input(&user.password){
        return Ok(HttpResponse::BadRequest().finish());
    }
    let hash_secret = get_env_var("HASH_SECRET").expect("HASH_SECRET must be set!");
    let mut hasher = Hasher::default();
    let hash = hasher.with_password(user.password).with_secret_key(hash_secret).hash().unwrap();
    user.password = hash;
    let username = user.username.to_owned();
    db::create_user(&db, user)
        .await
        .map(|id| HttpResponse::Ok().json( format!("\"id\":{},\"username\":{}",id, username) ))
        .map_err(|_e| ServiceError::InternalServerError)
}

#[get("/auth")]
async fn basic_auth(db: web::Data<Pool>, credentials: BasicAuth) -> impl Responder{
    let jwt_secret: Hmac<Sha256> = Hmac::new_from_slice(
        get_env_var("JWT_SECRET").expect("JWT_SECRET must be set!").as_bytes()
    ).unwrap();
    let username = credentials.user_id();
    let password = credentials.password();
  
    if !is_valid_user_input(&username) {
        return HttpResponse::Unauthorized().json("Must provide username and password");
    }

    match password {
        None => HttpResponse::Unauthorized().json("Must provide username and password"),
        Some(pass) =>{
            
            if !is_valid_user_input(&pass) {
                return HttpResponse::Unauthorized().json("Must provide username and password");
            }
            let res = db::find_user(&db, username.to_owned()).await;
            match res {
                Ok(user) =>{ 
                    //println!("username={}\nuser.password={:?}\npass={}",username,user.password,pass);

                    let hash_secret = get_env_var("HASH_SECRET").expect("HASH_SECRET must be set!");
                    let mut verifier = Verifier::default();
                    let is_valid = verifier
                        .with_hash(user.password)
                        .with_password(pass)
                        .with_secret_key(hash_secret)
                        .verify()
                        .unwrap(); 
                    if is_valid {
                        let claims = TokenClaims{id: user.id};
                        let token_str = claims.sign_with_key(&jwt_secret).unwrap();
                        HttpResponse::Ok().json(token_str)
                    }else{
                        HttpResponse::Unauthorized().json("Incorrect username or password")
                    }
                },
                Err(err) =>{ 
                    HttpResponse::InternalServerError().json(format!("{:?}",err))
                }
            }
        }
    }
}

#[get("/users")]
async fn get_users(hb: web::Data<Handlebars<'_>>, req_user: Option<web::ReqData<TokenClaims>>, db: web::Data<Pool>) -> Result<HttpResponse, ServiceError> { 
    match req_user{
        Some(_user) => {
            db::get_all_users(&db).await.map(|user| HttpResponse::Ok().json(user))
            .map_err(|e| ServiceError::InternalServerError)
        },
        _ => Ok(HttpResponse::Unauthorized().json("Unable to verify identity"))
    } 
}

#[get("/user")]
async fn get_user_by_id(hb: web::Data<Handlebars<'_>>, db: web::Data<Pool>, req_user: Option<web::ReqData<TokenClaims>>) -> Result<HttpResponse, ServiceError> { 
    match req_user{
        Some(user) => {
            db::get_user_by_id(&db, user.id).await.map(|user| HttpResponse::Ok().json(user))
            .map_err(|_e| ServiceError::InternalServerError)            
        },
        _ => Ok(HttpResponse::Unauthorized().json("Unable to verify identity"))
    } 
}
 
#[post("/create-article")]
async fn create_article(db: web::Data<Pool>, req_user: Option<web::ReqData<TokenClaims>>, body: web::Json<db::CreateArticlesBody>) -> Result<HttpResponse, ServiceError> { 
    match req_user{
        Some(user) => {
            let new_article: db::CreateArticlesBody = body.into_inner();
            if !is_valid_user_input(&new_article.title) || !is_valid_user_input(&new_article.content){
                return Ok(HttpResponse::BadRequest().finish());
            }
            match db::create_article(&db,new_article,user.id).await{
                Ok(article ) => Ok(HttpResponse::Ok().json(article)) ,
                Err(e) => Ok(HttpResponse::InternalServerError().json(format!("{:?}",e)))
            }
        },
        _ => Ok(HttpResponse::Unauthorized().json("Unable to verify identity"))
    } 
}
 
#[delete("/users")]
async fn delete_user(db: web::Data<Pool>, req_user: Option<web::ReqData<TokenClaims>>) -> Result<HttpResponse, ServiceError> { 
    match req_user{
        Some(user) => { 
            match db::delete_user(&db, user.id).await{
              Ok(is_del ) => Ok(HttpResponse::Ok().json(is_del)) ,
              Err(e) => Ok(HttpResponse::InternalServerError().json(format!("{:?}",e)))
            }
        },
        _ => Ok(HttpResponse::Unauthorized().json("Unable to verify identity"))
    }
}

async fn favicon() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("authentication_api_password/static_files/favicon.ico")?)
}

async fn validator(req: actix_web::dev::ServiceRequest, credentials: BearerAuth) -> Result<actix_web::dev::ServiceRequest,(actix_web::Error,actix_web::dev::ServiceRequest)>{
    let jwt_secret: String = get_env_var("JWT_SECRET").expect("JWT_SECRET must be set!");
    let key: Hmac<Sha256> = Hmac::new_from_slice(jwt_secret.as_bytes()).unwrap();
    let token_string = credentials.token();

    let claims: Result<TokenClaims, &str> = token_string.verify_with_key(&key).map_err(|_|"Invalid token");

    match claims {
        Ok(value) => {
            req.extensions_mut().insert(value);
            Ok(req)
        },
        Err(_) => {
            let config = req.app_data::<bearer::Config>().cloned().unwrap_or_default().scope("");      
            Err((AuthenticationError::from(config).into(),req))
        } 
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    dotenv::from_filename(std::path::Path::new("authentication_api_password/.env")).ok();
    
    let mut hbars = Handlebars::new();
    hbars.register_templates_directory("authentication_api_password/templates/", DirectorySourceOptions::default()).unwrap();
    let hbars_ref = web::Data::new(hbars);
      
    let url_db = dotenv::var("DB").expect("DB must be set!");
    // connect to SQLite DB
    let manager = SqliteConnectionManager::file(url_db).with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE);
    let pool = Pool::new(manager).unwrap();

    // load TLS keys
    // Для наших тестовых целей на локальном хосте достаточно, так называемого, self-signed certificate:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout cert/key.pem -out cert/cert.pem -days 365 -subj '/CN=localhost'`
    // password: 12345
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("authentication_api_password/cert/key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("authentication_api_password/cert/cert.pem").unwrap();

    HttpServer::new(move || {   
        let prometheus = PrometheusMetricsBuilder::new("api").endpoint("/metrics").build().unwrap();
        let bearer_middleware = HttpAuthentication::bearer(validator);
        App::new()
            .wrap(
                Logger::new("All headers %{AH}xi")
                .custom_request_replace("AH", |req|  {
                    println!("\n");
                    for h in req.headers(){
                        println!("{name:-<width$}{value:?}",width=28,name=h.0.as_str().to_uppercase(), value=h.1.to_str());   
                    } 
                    println!("\n");
                    "".to_owned()
                    }
                ))
             .wrap(
                Logger::new("
                Peer IP address=%a
                First line of request=%r
                Response status code=%s
                Size of response in bytes=%b
                Referer=%{Referer}i
                User-Agent=%{User-Agent}i
                Time=%T
                Content-type=%{Content-type}i
                Access-Control-Allow-Origin=%{Access-Control-Allow-Origin}i
                Set-Cookie=%{Set-Cookie}i
                \n+-+-+-+-+-+-+-++-+-+-\n") 
            ) 
            .wrap(prometheus.clone())
            .wrap(
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
            )
            .app_data(hbars_ref.clone())
            .app_data(web::Data::new(pool.clone()))
            .service(basic_auth)
            .service(index) 
            .service(create_user)
            .route("/favicon.ico", web::get().to(favicon))
            .service(
                web::scope("/api")
                .wrap(bearer_middleware)
                .service(get_users)
                .service(get_user_by_id)
                .service(delete_user)
                .service(create_article)
            )
            .service(
                // use https://127.0.0.1:8080/static
                actix_files::Files::new("/static", "authentication_api_password/static_files")
                    .show_files_listing()
                    .use_last_modified(true)
                    .prefer_utf8(true),
            )
            
            .default_service(web::route().guard(guard::Not(guard::Get())).to(HttpResponse::MethodNotAllowed))
    })
    .workers(4) 
    .bind_openssl("127.0.0.1:8070", builder)?
    .run()
    .await
}
 

#[derive(Debug, Display)]
pub enum ServiceError {
    #[display(fmt = "Internal Server Error")]
    InternalServerError,

    #[display(fmt = "BadRequest: {}", _0)]
    BadRequest(String),

    #[display(fmt = "JWKSFetchError")]
    JWKSFetchError,
}

impl actix_web::error::ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServiceError::InternalServerError => {
                HttpResponse::InternalServerError().json("Internal Server Error, Please try later")
            }
            ServiceError::BadRequest(ref message) => HttpResponse::BadRequest().json(message),
            ServiceError::JWKSFetchError => {
                HttpResponse::InternalServerError().json("Could not fetch JWKS")
            }
        }
    }
    fn status_code(&self) -> actix_web::http::StatusCode {
        match *self {
            ServiceError::InternalServerError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            ServiceError::BadRequest(_) => actix_web::http::StatusCode::BAD_REQUEST,
            ServiceError::JWKSFetchError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
