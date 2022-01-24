DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS record;

CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  username_encrypted BLOB NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE record (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL,
  site_url TEXT NOT NULL,
  used_login TEXT NOT NULL,
  used_email TEXT NOT NULL,
  used_password BLOB NOT NULL,
  FOREIGN KEY (author_id) REFERENCES user (id)
);