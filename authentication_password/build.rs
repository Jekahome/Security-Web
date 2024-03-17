use std::process::Stdio;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = std::process::Command::new("sh")
    .arg("db/setup_db.sh")
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child.wait().unwrap();
   Ok(())
} 

/*
sqlite client:
 
$ sqlite3 database.db
sqlite> .tables
sqlite> select * from users;
sqlite> insert into users (username,password) values  ('kkk', 'kkk' );
sqlite> insert into messages (id,user_id,msg) values (1, 1, 'hello');
sqlite> insert into messages (id,user_id,msg) values (2, 1, 'world');
sqlite> delete from messages where id > 0;
*/