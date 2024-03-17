use std::env;
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
sqlite> select * from messages;
sqlite> insert into users (id,name,email,password) values  (1, 'kkk', 'kkk@mail.com', '1234');
sqlite> insert into messages (id,user_id,msg) values (1, 1, 'hello');
sqlite> insert into messages (id,user_id,msg) values (2, 1, 'world');
sqlite> delete from messages where id > 0;
*/