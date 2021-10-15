CREATE TABLE IF NOT EXISTS users (
    id BLOB PRIMARY KEY NOT NULL,   -- UUID representing this user
    username TEXT NOT NULL UNIQUE,  -- unique username
    email TEXT NOT NULL UNIQUE      -- unique email
);

CREATE TABLE IF NOT EXISTS passwords (
    user_id BLOB NOT NULL UNIQUE,   -- foreign key identifying what user this totp belongs to
    password TEXT NOT NULL,         -- hashed password
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS totp (
    user_id BLOB NOT NULL UNIQUE,   -- foreign key identifying what user this totp belongs to
    key TEXT NOT NULL,              -- secret key used in HMAC computation
    step INT8 NOT NULL DEFAULT 30,   -- step (in seconds) to use for this totp
    base INT8 NOT NULL DEFAULT 0,    -- unix timestamp to use as base (usuaully unix epoch (0))
    digits INTEGER NOT NULL DEFAULT 6,  -- number of digits to use in totp code
    FOREIGN KEY(user_id) REFERENCES users(id)
);
