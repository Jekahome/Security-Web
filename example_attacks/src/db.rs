use std::{thread::sleep, time::Duration};
use actix_web::{error, web};
use rusqlite::{Statement, params, named_params};
use serde::{Deserialize, Serialize};

pub type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub type Connection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;
  
#[allow(clippy::enum_variant_names)]
pub enum Queries {
    GetMsg(i64),
    NewMsg(i64,String),
    Clear
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Messages {
    id: i64,
    user_id: i64,
    msg: String,
}

pub async fn execute(pool: &Pool, query: Queries) -> Result<Vec<Messages>, actix_web::Error> {
    let pool = pool.clone();

    let conn = web::block(move || pool.get())
        .await?
        .map_err(error::ErrorInternalServerError)?;

    web::block(move || {
        match query {
            Queries::GetMsg(user_id) => get_msg(conn, user_id),
            Queries::NewMsg(user_id, msg) => new_msg(conn, user_id, msg),
            Queries::Clear => {clear(conn);Ok(vec![])}
        }
    })
    .await?
    .map_err(error::ErrorInternalServerError)
}

fn get_msg(conn: Connection, user_id: i64) -> Result<Vec<Messages>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id,user_id,msg FROM messages WHERE user_id = ?1;")?;
   
    stmt
    .query_map([user_id], |row| {
        Ok(Messages {
            id: row.get(0)?,
            user_id: row.get(1)?,
            msg: row.get(2)?
        })
    })
    .and_then(Iterator::collect)
}

fn new_msg(conn: Connection, user_id: i64, msg: String) -> Result<Vec<Messages>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "INSERT INTO messages (user_id, msg) VALUES (:user_id, :msg);")?;
    stmt.execute(named_params!{":user_id": user_id, ":msg": msg})?;
    let messages_id = conn.last_insert_rowid();

    let new_msg = conn.query_row(
        "SELECT id,user_id,msg FROM messages WHERE id=:id",
        params![messages_id],
        |row| { 
            Ok(Messages{
                id: row.get::<&str,i64>("id").expect("Failed to parse field id"),
                user_id: row.get::<&str,i64>("user_id").expect("Failed to parse field user_id"),
                msg: row.get::<&str,String>("msg").expect("Failed to parse field msg")
            })
            
        },
    );
    if let Ok(new_msg) = new_msg {
        return Ok(vec![new_msg]);
    }

    Ok(vec![])
}

fn clear(conn: Connection) -> Result<(), rusqlite::Error>{
    conn.execute("delete from messages where id > 0;",[])?;
    Ok(())
}