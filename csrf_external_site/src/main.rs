use actix_web::{web, middleware, guard::{self, Guard}, App, HttpResponse, 
HttpRequest, HttpServer, Responder, Either, 
http::{self,header::{self,ContentType}} };

use actix_web::{get, post};// макросы роутинга
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_session::config::{ BrowserSession, CookieContentSecurity };
use actix_web::cookie::{ Key, SameSite };

use actix_files::NamedFile;
use awc::ws::Message;
use futures::StreamExt;
  
use std::{collections::HashMap, sync::RwLock};
use serde::{Serialize,Deserialize};
use serde_json::json;
use handlebars::{Handlebars, DirectorySourceOptions};
use std::collections::btree_map::BTreeMap;
 
#[get("/")]
async fn index(hb: web::Data<Handlebars<'_>>) -> Result<HttpResponse, actix_web::Error> {  
    let data = json!({"layout": {"title":"CSRF-атака с ативным действием"} });
    let content = hb.render(&"index", &data).unwrap(); 
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}
 
#[get("/no-action")]
async fn no_action(hb: web::Data<Handlebars<'_>>) -> Result<HttpResponse, actix_web::Error> {  
    let data = json!({"layout": {"title":"CSRF-атака без активного действия"} });
    let content = hb.render(&"no-action", &data).unwrap(); 
    Ok(HttpResponse::Ok().content_type(ContentType::html()).body(content)) 
}

async fn favicon() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("csrf_external_site/static_files/favicon.ico")?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    let mut hbars = Handlebars::new();
    hbars.register_templates_directory("csrf_external_site/templates/", DirectorySourceOptions::default()).unwrap();
    let hbars_ref = web::Data::new(hbars);

    HttpServer::new(move || {
        let logger = actix_web::middleware::Logger::default();
        App::new()
            .app_data(hbars_ref.clone())
            .service(index) 
            .service(no_action)
            .service(
                // use http://127.0.0.1:8080/static
                actix_files::Files::new("/static", "csrf_external_site/static_files")
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
    .bind("127.0.0.1:8090")?
    .run()
    .await
}
