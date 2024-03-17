CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL, 
  email TEXT NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  msg TEXT NOT NULL
);

insert into users (id,name,email,password) values (1, 'Kent', 'Kent@gmail.com','1234');
insert into messages (id,user_id,msg) values (1, 1, '<h1>hello</h1>');
insert into messages (id,user_id,msg) values (2, 1, 'world');
 