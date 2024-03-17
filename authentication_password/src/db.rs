#![allow(dead_code)]

use actix_web::{error, web};
use rusqlite::{named_params};
use serde::{Deserialize, Serialize};
 
use uuid::Uuid;

pub type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
//pub type Connection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;
  

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
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

#[derive(Debug,  serde::Deserialize)]
pub struct InputUser {
    pub username: String,
    pub password: String, 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthUser {
    id: Uuid,
    username: String,
    password: String,
}
 
pub async fn create_user(pool: &Pool, user: InputUser) -> Result<Uuid, actix_web::Error> {
    let pool = pool.clone();

    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;
    let id =  Uuid::new_v4();
    web::block(move || {
        if let Ok(mut stmt) = conn.prepare(
            "INSERT INTO users (id, username, password, created_at) VALUES (:user_id,:username,:password,:created_at);"){
                let res = stmt.execute(named_params!{
                    ":user_id": id,
                    ":username": user.username,
                    ":password": user.password,
                    ":created_at": chrono::Local::now().naive_local()
                }).expect("Insert user failed");  
                println!("\nINSERT {}\n",res);       
            }
            id
        }
    ).await.map_err(error::ErrorInternalServerError)
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

pub async fn get_user_by_id(pool: &Pool, user_id: Uuid) -> Result<User, actix_web::Error> {
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


pub async fn delete_user(pool: &Pool, user_id: Uuid) -> Result<bool, actix_web::Error>{
    let pool = pool.clone();
    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;
    web::block(move || {
        let mut stmt = conn.prepare("DELETE FROM users WHERE id=:id").expect("DELETE user failed"); 
        stmt.execute(named_params!{":id": user_id}).is_ok()          
    }).await.map_err(error::ErrorInternalServerError)
}

pub async fn change_password(pool: &Pool, user_id: Uuid, password: String) -> Result<(), actix_web::Error>{
    let pool = pool.clone();

    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;

    web::block(move || {
        let mut stmt = conn.prepare( "UPDATE users SET password=:password WHERE id=:user_id;").expect("UPDATE user failed"); 
      
        stmt.execute(named_params!{
            ":user_id": user_id,
            ":password": password,
        }).expect("UPDATE user failed");            
            
    }).await.map_err(error::ErrorInternalServerError)
}