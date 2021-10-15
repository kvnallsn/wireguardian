-- DHCP Lease Table
CREATE TABLE IF NOT EXISTS dhcp (
    id TEXT PRIMARY KEY NOT NULL,                           -- unique id of this lease
    session_id TEXT NOT NULL,                               -- session that checked out this lease
    ip INT NOT NULL,                                        -- ip that was leased out
    active BOOL NOT NULL DEFAULT true,                      -- if this lease is active (true) or expired (false)
    created DATETIME NOT NULL DEFAULT current_timestamp,    -- date/time this lease was created
    released DATETIME NULL DEFAULT NULL,                    -- date/time this lease was released
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

-- trigger to update modified timestamp when the expired field is updated/modified
CREATE TRIGGER IF NOT EXISTS update_dhcp_released_time UPDATE OF active ON dhcp 
    BEGIN
        UPDATE dhcp SET released = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

-- trigger to mark lease as expired when a session ends
CREATE TRIGGER IF NOT EXISTS release_dhcp_on_session_end UPDATE OF expired ON sessions
    BEGIN
        UPDATE dhcp SET active = false WHERE session_id = NEW.id;
    END;
