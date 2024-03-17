use std::{thread::sleep, time::Duration};
use actix_web::{error, web};
use rusqlite::{Statement, params, named_params};
use serde::{Deserialize, Serialize};
use chrono::DateTime;

pub type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub type Connection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;
  

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password: String,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug)]
pub struct NewUser<'a> {
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub email: &'a str,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InputUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthUser {
    id: i64,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
pub struct CreateArticlesBody {
    pub title: String,
    pub content: String,
}

#[derive(Serialize, Deserialize)]
pub struct Article {
    id: i64,
    user_id: i64,
    title: String,
    content: String,
    created_at: chrono::NaiveDateTime,
}

pub async fn create_article(pool: &Pool, article: CreateArticlesBody,user_id: i64) -> Result<Article, actix_web::Error>{
    let pool = pool.clone();

    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;
 
        web::block(move || {
            let created_at = chrono::Local::now().naive_local();
            if let Ok(mut stmt) = conn.prepare(
                "INSERT INTO articles (user_id,title,content,created_at) VALUES (:user_id,:title,:content,:created_at);"){
                    
                    stmt.execute(named_params!{
                        ":user_id": user_id,
                        ":title": article.title,
                        ":content": article.content,
                        ":created_at": created_at
                    }).expect("Insert article failed");                
                }
                Article{
                    id:conn.last_insert_rowid(),
                    user_id: user_id,
                    title: article.title,
                    content: article.content,
                    created_at:created_at
                }
            
        }).await.map_err(error::ErrorInternalServerError)
 
}

pub async fn create_user(pool: &Pool, user: InputUser) -> Result<i64, actix_web::Error> {
    let pool = pool.clone();

    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;

    web::block(move || {
        if let Ok(mut stmt) = conn.prepare(
            "INSERT INTO users (username,password,created_at) VALUES (:username,:password,:created_at);"){

                stmt.execute(named_params!{
                    ":username": user.username,
                    
                    ":password": user.password,
                    ":created_at": chrono::Local::now().naive_local()
                }).expect("Insert user failed");                
            }
        conn.last_insert_rowid()
    }).await.map_err(error::ErrorInternalServerError)
}

pub async fn find_user(pool: &Pool, username: String) -> Result<User, actix_web::Error> {
    let pool = pool.clone();

    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;

    web::block(move || {
        let mut stmt = conn.prepare(
            "SELECT id,username,password,created_at FROM users WHERE username=:username;")?;
       
        stmt
        .query_row(named_params!{":username": username}, |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password: row.get(2)?,
                created_at: row.get::<usize, chrono::NaiveDateTime>(3)?  
            })
        })
         
    })
    .await?
    .map_err(error::ErrorInternalServerError)

}


pub async fn get_all_users(pool: &Pool) -> Result<Vec<User>, actix_web::Error> {
    let pool = pool.clone();

    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;
    
    web::block(move || {
        let mut stmt = conn.prepare(
            "SELECT id,username,password,created_at FROM users;")?;
 
        stmt
        .query_map([], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password: row.get(2)?,
                created_at: row.get::<usize, chrono::NaiveDateTime>(3)?
            })
        })
        .and_then(Iterator::collect)
    })
    .await?
    .map_err(error::ErrorInternalServerError)
}

pub async fn get_user_by_id(pool: &Pool, user_id: i64) -> Result<User, actix_web::Error> {
    let pool = pool.clone();

    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;

    web::block(move || {
        let mut stmt = conn.prepare(
            "SELECT id,username,password,created_at FROM users WHERE id=:user_id;")?;
       
        stmt
        .query_row(named_params!{":user_id": user_id}, |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password: row.get(2)?,
                created_at: row.get::<usize, chrono::NaiveDateTime>(3)?  
            })
        })
         
    })
    .await?
    .map_err(error::ErrorInternalServerError)
}


pub async fn delete_user(pool: &Pool, user_id: i64) -> Result<bool, actix_web::Error>{
    let pool = pool.clone();
    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;
    web::block(move || {
        if let Ok(mut stmt) = conn.prepare(
            "DELETE FROM users WHERE id=:id"){
                return stmt.execute(named_params!{":id": user_id}).is_ok();           
            }
        true
    }).await.map_err(error::ErrorInternalServerError)
}