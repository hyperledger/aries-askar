
-- This SQL file contains the database schema for a DB2 server.
--

CREATE TABLE config (
    name VARCHAR(1022) NOT NULL,
    value CLOB,
    PRIMARY KEY(name)
);

CREATE TABLE profiles (
    id BIGINT NOT NULL GENERATED ALWAYS AS IDENTITY,
    name VARCHAR(1022) NOT NULL,
    reference CLOB NULL,
    profile_key BLOB NULL,
    PRIMARY KEY(id)
);

CREATE UNIQUE INDEX ix_profile_name ON profiles(name);

CREATE TABLE items (
    id BIGINT NOT NULL GENERATED ALWAYS AS IDENTITY,
    profile_id BIGINT NOT NULL,
    kind SMALLINT NOT NULL,
    category VARCHAR(500) NOT NULL,
    name VARCHAR(500) NOT NULL,
    value BLOB NOT NULL,
    expiry TIMESTAMP NULL,
    PRIMARY KEY(id),
    FOREIGN KEY(profile_id) REFERENCES profiles(id)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX ix_items_uniq ON items(profile_id, kind, category, name);
CREATE INDEX ix_items_profile_id ON items(profile_id);

CREATE TABLE items_tags (
    id BIGINT NOT NULL GENERATED ALWAYS AS IDENTITY,
    item_id BIGINT NOT NULL,
    name VARCHAR(500) NOT NULL,
    value VARCHAR(500) NOT NULL,
    plaintext SMALLINT NOT NULL,
    PRIMARY KEY(id),
    FOREIGN KEY(item_id) REFERENCES items(id)
        ON DELETE CASCADE
);

CREATE INDEX ix_items_tags_item_id ON items_tags(item_id);
CREATE INDEX ix_items_tags_name ON items_tags(name, value);

COMMIT;
