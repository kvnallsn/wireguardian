-- sessions table for tracking logged in user sessions
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY NOT NULL,                               -- uuid / strong random session identifier
    user_id TEXT NOT NULL,                                      -- user id of owning user
    expired BOOL NOT NULL DEFAULT true,                         -- flag to check for expiration
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,        -- date/time this session was created
    modified DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,       -- date/time this session was last modified
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- trigger to update modified timestamp when the expired field is updated/modified
CREATE TRIGGER IF NOT EXISTS update_sessions_modified_time UPDATE OF expired ON sessions
    BEGIN
        UPDATE sessions SET modified = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
