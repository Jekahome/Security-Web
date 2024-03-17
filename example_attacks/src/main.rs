use actix_web::{web, middleware::{self,Logger}, guard::{self, Guard}, App, HttpResponse, 
HttpRequest, HttpServer, Responder, Either, 
http::{self,header::{self,ContentType}} };

use actix_web::{get, post};// макросы роутинга
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_session::config::{ BrowserSession, CookieContentSecurity };
use actix_web::cookie::{ Key, SameSite };
use actix_cors::Cors;
use actix_multipart::Multipart;
 
use rand::rngs::StdRng;

use actix_files::NamedFile;
use awc::ws::Message;
use futures::StreamExt;
use rusqlite::OpenFlags;

use std::{collections::HashMap, sync::RwLock};
use serde::{Serialize,Deserialize};
use serde_json::json;
use handlebars::{Handlebars, DirectorySourceOptions};
use std::collections::btree_map::BTreeMap;
use r2d2_sqlite::SqliteConnectionManager;

mod db;
use db::{Pool, Queries, Messages};

#[get("/")]
async fn index(hb: web::Data<Handlebars<'_>>) -> Result<HttpResponse, actix_web::Error> {// 127.0.0.1:8080/ 
    // .map_err(|e| actix_web::error::ErrorBadRequest(e))?;
    let mut pages = BTreeMap::<&str,&str>::new();
    pages.insert("/html-injection-saved", "HTML Injection - Saved HTML");
    let data = json!({"layout": {"title":"WEB Security"}, "pages": pages});
    let content = hb.render(&"index", &data).unwrap();// templates/index.hbs
    Ok(HttpResponse::Ok()
    .content_type(ContentType::html())
    .body(content)) 
}
 
#[get("/html-injection-saved")]
async fn html_injection_saved(hb: web::Data<Handlebars<'_>>, db: web::Data<Pool>) -> Result<HttpResponse, actix_web::Error> {// 127.0.0.1:8080/html-injection
    let user_id = 1i64;
    let msg = db::execute(&db, Queries::GetMsg(user_id)).await?;
    let data = json!({"layout": {"title":"HTML Injection - Saved HTML"},"msg": msg});
    let content = hb.render(&"html_injection_saved", &data).unwrap();// templates/html_injection_saved.hbs
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}
 
#[derive(Serialize, Deserialize)]
struct InputGetMessages {
    user_id: i64,
}

#[derive(Serialize, Deserialize)]
struct InputPostMessages {
    user_id: i64,
    msg: String
}

#[post("/html-injection-get-messages")]
async fn html_injection_saved_get_msg(db: web::Data<Pool>, input: web::Json<InputGetMessages>) -> Result<web::Json<Vec<Messages>>, actix_web::Error>  {
    let msg = db::execute(&db, Queries::GetMsg(input.user_id)).await?;
    println!("{:?}",msg);
    Ok(web::Json(msg))
}

/*
Response Json
Request `web::Json`

`curl -d '{"user_id":1, "messages": "new message"}' -H "Content-Type: application/json" -X POST http://127.0.0.1:8080/html-injection-saved-get-messages`
*/
#[post("/html-injection-saved-new-messages")]
async fn html_injection_saved_new_msg(db: web::Data<Pool>, input: web::Json<InputPostMessages>) -> Result<web::Json<Vec<Messages>>, actix_web::Error>  {
    let new_msg = db::execute(&db, Queries::NewMsg(input.user_id, input.msg.clone())).await?;
    println!("{:?}",new_msg);
    Ok(web::Json(new_msg))
}

/*
Request `web::Form`  
  
`curl -d "user_id=1&msg=hello+world" -H "Content-Type: application/x-www-form-urlencoded" -X POST 127.0.0.1:8080/html-injection-saved-new-messages-form`
*/
#[post("/html-injection-saved-new-messages-form")]
async fn html_injection_saved_new_msg_form( db: web::Data<Pool>, input: Either<web::Form<InputPostMessages>, String> ) -> Result<impl Responder, actix_web::Error>  {
    match input {
        Either::Left(form) => {
            db::execute(&db, Queries::NewMsg(form.user_id, form.msg.clone())).await?;
        },
        Either::Right(s) => {
            let re = regex::Regex::new(r"msg=(.*)\W*user_id=(.*)").unwrap();
            let caps = re.captures(&s).unwrap();
            if caps.len() == 3{
                if let Ok(user_id) = caps[2].trim().parse::<i64>(){   
                    db::execute(&db, Queries::NewMsg(user_id, caps[1].to_owned())).await?;
                }
            } 
        },
    }
 
    // TODO: SEE_OTHER converse POST to GET
    Ok(web::Redirect::to("/html-injection-saved").using_status_code(http::StatusCode::SEE_OTHER).see_other())
    //Ok(HttpResponse::Found().append_header(("location", "/html-injection")).finish())
}

#[post("/html-injection-saved-db-clear")]
async fn html_injection_saved_db_clear( db: web::Data<Pool> ) -> Result<impl Responder, actix_web::Error>  {
    db::execute(&db, Queries::Clear).await?;println!("clear");
    Ok(web::Redirect::to("/html-injection-saved").using_status_code(http::StatusCode::SEE_OTHER).see_other())
}

#[derive(Serialize, Deserialize)]
struct InputGetMessagesReflected {
    name: String,
    msg: String
}
#[get("/html-injection-reflected-get")]
async fn html_injection_reflected_get(hb: web::Data<Handlebars<'_>>, query: Option<web::Query<InputGetMessagesReflected>>) -> Result<HttpResponse, actix_web::Error> { 
    let mut name = "".into();
    if let Some(q) = query {
        name = q.name.to_owned();
    }
    let data = json!({"layout": {"title":"HTML Injection - Reflected (GET)"}, "name":name});
    let content = hb.render(&"html_injection_reflected_get", &data).unwrap(); 
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}


#[derive(Serialize, Deserialize, Debug)]
struct InputHPP {
    url: String,
    name: String,
    msg: String
}

#[get("/http-parameter-pollution")]
async fn http_parameter_pollution(hb: web::Data<Handlebars<'_>> ) -> Result<HttpResponse, actix_web::Error> { 
     
    let data = json!({"layout": {"title":"HTTP Parameter Pollution"}});
    let content = hb.render(&"http_parameter_pollution", &data).unwrap(); 
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}
 
#[post("/http-parameter-pollution")]
async fn http_parameter_pollution_post(bytes: actix_web::web::Bytes ) -> Result<impl Responder, actix_web::Error> { 
    let res =  std::str::from_utf8(&bytes)?;
    let params:Vec<String> = res.split('&').map(|v|v.to_owned()).collect();
    let mut map = HashMap::new();
    for p in params{
        let mut kv:Vec<String> = p.split('=').map(|v|v.to_owned()).collect();
        if kv.len() == 2{
            map.insert(kv[0].to_owned(),kv[1].trim().to_owned());
        }
    }
    let mut url = "/http-parameter-pollution".to_owned();
    if map.contains_key("url"){
        url = map.get("url").unwrap().to_owned();
    }
    Ok(web::Redirect::to(url).using_status_code(http::StatusCode::SEE_OTHER).see_other())
}

#[derive(Serialize, Deserialize)]
struct CRLFinjection {
    name: String,
    msg: String,
}

#[get("/crlf-injection")]
async fn crlf_injection(query: Option<web::Query<CRLFinjection>>, hb: web::Data<Handlebars<'_>> ) -> Result<HttpResponse, MyError> { 
    let mut redirect_after_login = "http://127.0.0.1:8080/crlf-injection?".to_owned();
    let mut msg = "".to_owned();
    if let Some(q) = query{
        msg = q.msg.to_owned();
        redirect_after_login.push_str(&format!("name={}&msg={}",q.name,q.msg));
    }
    let data = json!({"layout": {"title":"CRLF (Carriage Return Line Feed)"},"redirect_after_login":redirect_after_login});
    let content = hb.render(&"crlf_injection", &data).unwrap(); 
    Ok(actix_web::HttpResponseBuilder::new(http::StatusCode::OK)
        .insert_header(header::ContentType(mime::TEXT_HTML))
        // .insert_header(("X-Your-Name", msg))
        .body(content)
    )
}
 

/*
`curl http://127.0.0.1:8080/get-session`
*/
#[get("/get-session")]
async fn get_session(session: Session) -> impl actix_web::Responder {
    match session.get::<String>("delivery_address") {
        Ok(message_option) => {
            match message_option {
                Some(message) => HttpResponse::Ok().body(message),
                None => HttpResponse::NotFound().body("Not set.")
            }
        }
        Err(_) => HttpResponse::InternalServerError().body("Session error.")
    }
}

#[derive(serde::Deserialize)]
struct CookieModel {
    delivery_address: String
}
/*
`curl -d '{ "delivery_address": "new delivery address"}' -H "Content-Type: application/json" -X POST http://127.0.0.1:8080/set-session-json`
*/
#[post("/set-session-json")]
async fn set_session_json( session: Session, model: web::Json<CookieModel>) -> impl actix_web::Responder {
    match session.insert("delivery_address", model.delivery_address.clone()) {
        Ok(_) => HttpResponse::Created().content_type(ContentType::json()).body(model.delivery_address.clone()),
        Err(_) => HttpResponse::InternalServerError().body("Error.")
    }
}

/*
`curl -d "delivery_address=new+delivery+address" -H "Content-Type: application/x-www-form-urlencoded" -X POST http://127.0.0.1:8080/set-session-form`
*/
#[post("/set-session-form")]
async fn set_session_form( req: HttpRequest, session: Session, model: web::Form<CookieModel>) -> Either<impl actix_web::Responder, HttpResponse>  {
    match session.insert("delivery_address", model.delivery_address.clone()) {
        Ok(_) => {
            Either::Left(web::Redirect::to("/csrf").using_status_code(http::StatusCode::SEE_OTHER).see_other())
        },
        Err(_) => Either::Right(HttpResponse::InternalServerError().finish())
    }
}


#[get("/csrf")]
async fn csrf(req: HttpRequest, session: Session, hb: web::Data<Handlebars<'_>> ) -> Result<HttpResponse, MyError> { 
    if let Ok(cookies) = req.cookies(){
        for cookie in cookies.iter(){
            println!("cookie={}",cookie.encoded());
        }
    }

    let mut delivery_address = "Not set.".into();
    if let Ok(Some(val)) = session.get::<String>("delivery_address"){
        delivery_address = val.to_owned();
    }
    let data = json!({"layout": {"title":"Cross Site Request Forgery (CSRF-атаки)"},"delivery_address":delivery_address});
    let content = hb.render(&"csrf", &data).unwrap(); 
    Ok(HttpResponse::Ok()
    .cookie(
        actix_web::cookie::Cookie::build("CUSTOM-COOKIE", "567")
            //.domain("www.rust-lang.org")
            .path("/")
            .secure(true)
            .http_only(true)
            .finish(),
    )
    .content_type(ContentType::html()).body(content)) 
}


#[derive(serde::Deserialize)]
struct XSSModel {
    message: String
}

#[get("/xss")]
async fn xss(query: Option<web::Query<XSSModel>>, hb: web::Data<Handlebars<'_>> ) -> Result<HttpResponse, actix_web::Error> { 
    let mut message = "".to_string();
    if let Some(q) = query{
        message = q.message.clone();
    }
    let data = json!({"layout": {"title":"Cross Site Scripting Attacks (XSS)"},"message":message});
    let content = hb.render(&"xss", &data).unwrap(); 
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}

#[get("/xss-ajax")]
async fn xss_ajax( req: HttpRequest, model: web::Query<XSSModel>) -> Result<HttpResponse, MyError>  {
    println!("{}",req.query_string());// message=dff
    Ok(HttpResponse::Ok().content_type(ContentType::json()).body(model.message.clone())) 
}

#[post("/xss-img")]
async fn xss_img(mut payload: web::Payload) -> Result<HttpResponse, actix_web::Error> {
    let body: actix_web::web::Bytes = payload.to_bytes().await?;
    let s:Vec<String> = format!("{:?}",&body).split_whitespace().map(|s|s.to_owned()).collect();
    let body:Vec<String> = s[2].splitn(2,'=').map(|s|s.to_owned()).collect();
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(body[1].clone())) 
}

async fn favicon() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("example_attacks/static_files/favicon.ico")?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    let mut hbars = Handlebars::new();
    hbars.register_templates_directory("example_attacks/templates/", DirectorySourceOptions::default()).unwrap();
    let hbars_ref = web::Data::new(hbars);

    // connect to SQLite DB
    let manager = SqliteConnectionManager::file("example_attacks/db/database.db").with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE);
    let pool = Pool::new(manager).unwrap();

    //let data = web::Data::new(RwLock::new(AppState::default()));

    HttpServer::new(move || {   
        let json_config = web::JsonConfig::default()
            .limit(4096).error_handler(|err, _req| {
                // create custom error response
                actix_web::error::InternalError::from_response(err, HttpResponse::Conflict().finish()).into()
            });
        let form_config = web::FormConfig::default()
            .limit(4096).error_handler(|err, _req| {
                // create custom error response
                actix_web::error::InternalError::from_response(err, HttpResponse::Conflict().finish()).into()
            });
 
        App::new()
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
                \n"))
             
            .wrap(
                // Сохранение и управление состоянием между запросами в CookieSessionStore.
                // SessionMiddleware<CookieSessionStore>
                SessionMiddleware::builder(
                    CookieSessionStore::default(), Key::from(&[0; 64])
                )
                .cookie_name(String::from("my-kata-cookie")) // arbitrary name
                .cookie_secure(false) // true=https only
                .session_lifecycle(BrowserSession::default()) // expire at end of session
                .cookie_same_site(SameSite::Strict) 
                .cookie_content_security(CookieContentSecurity::Private) // encrypt
                .cookie_same_site(SameSite::Lax)
                .cookie_http_only(true) // disallow scripts from reading
                .build()
            )
            .wrap(
                Cors::permissive() // без ограничений
                /* Cors::default() 
                .allowed_origin_fn(|h,r|->bool{
                    println!("----HeaderValue{:?} \n\nRequestHead={:?}\n\n",h,r);
                    true
                })
                .allowed_origin("http://127.0.0.1:8090")
                .allowed_methods(vec!["GET", "POST"])
                .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                .allowed_header(header::CONTENT_TYPE)
                .max_age(3600) */
            )
            .app_data(hbars_ref.clone())
            .app_data(web::Data::new(pool.clone()))
            //.app_data(data.clone())
            
            .service(index) 
            .service(html_injection_saved)
            .service(html_injection_saved_get_msg)
            .service(html_injection_saved_new_msg)
            .service(html_injection_saved_new_msg_form)
            .service(html_injection_saved_db_clear)
            .service(html_injection_reflected_get)
            .service(http_parameter_pollution)
            .service(http_parameter_pollution_post)
            .service(crlf_injection)
            .service(csrf)
            .service(get_session)
            .service(set_session_json)
            .service(set_session_form)
            .service(xss)
            .service(xss_ajax)
            .service(xss_img)
            .service(
                // use http://127.0.0.1:8080/static
                actix_files::Files::new("/static", "example_attacks/static_files")
                    .show_files_listing()
                    .use_last_modified(true)
                    .prefer_utf8(true),
            )
            .route("/favicon.ico", web::get().to(favicon))
            .default_service(
                web::route()
                    .guard(guard::Not(guard::Get()))
                    .to(HttpResponse::MethodNotAllowed),
            )
    })
    .workers(4) 
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
 

// Носитель данных состояния между запросами 
/*#[derive(Default)]
struct AppState {
    counter: usize,
    app_name: String
}*/

// actix_web::guard::Guard trait
// Фильтрует запросы с помощью actix_web::dev::RequestHead и входных параметров инициализации
struct MyGuard{
    filter:String
}
impl Guard for MyGuard{
    fn check(&self, ctx: &actix_web::guard::GuardContext<'_> ) -> bool {
        let head = ctx.head();
        if let Some(val) = head.headers.get("Host") {
            return val == &self.filter;
        }
        false
    }
}

use derive_more::{Display, Error};
#[derive(Debug, Display, Error)]
enum MyError {
    #[display(fmt = "internal error")]
    InternalError,

    #[display(fmt = "bad request")]
    BadClientData,

    #[display(fmt = "timeout")]
    Timeout,
}

impl actix_web::error::ResponseError for MyError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match *self {
            MyError::InternalError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            MyError::BadClientData => actix_web::http::StatusCode::BAD_REQUEST,
            MyError::Timeout => actix_web::http::StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

pub mod files {
    use std::io::Write;
    use actix_multipart::Multipart;
    use actix_web::{middleware, web, App, Error, HttpResponse, HttpServer};
    use futures::{StreamExt, TryStreamExt};

    pub async fn save_file(mut payload: Multipart, file_path: String) -> Option<String>{
        let mut filename = "".to_string();
        // iterate over multipart stream
        while let Ok(Some(mut field)) = payload.try_next().await {
            let content_type = field.content_disposition();
            filename = content_type.get_filename().unwrap().to_string();
            let filepath = format!("{}", file_path);

            // File::create is blocking operation, use threadpool
            let mut f = web::block(|| std::fs::File::create(filepath)).await.unwrap().unwrap();

            // Field in turn is stream of *Bytes* object
            while let Some(chunk) = field.next().await {
                let data = chunk.unwrap();
                // filesystem operations are blocking, we have to use threadpool
                f = web::block(move || f.write_all(&data).map(|_| f)).await.unwrap().unwrap();
            }
        } 
        Some(filename)
    }
}

// sessions
// https://actix.rs/docs/middleware#user-sessions

// authentication
// https://medium.com/swlh/user-authentication-in-rust-ee8116934d73

// https://www.reddit.com/r/rust/comments/gvaash/stuck_with_actix_and_supporting_redirect_to_login/

// https://dev.to/werner/practical-rust-web-development-authentication-3ppg