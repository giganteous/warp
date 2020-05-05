-- Your SQL goes here
CREATE TABLE todos (
    id bigserial primary key,
    text varchar NOT NULL,
    completed bool NOT NULL);
