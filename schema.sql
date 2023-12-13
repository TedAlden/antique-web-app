-- To execute this schema, run the command in a terminal:
-- sqlite3 database.db < schema.sql

-- Drop tables first, if they exist
-- DROP TABLE Users;
-- DROP TABLE TwoFA;
-- DROP TABLE SecurityQuestions;
-- DROP TABLE EvaluationRequests;
-- DROP TABLE LoginCounter;

-- Create tables
CREATE TABLE Users (
    Email TEXT PRIMARY KEY,
    Name TEXT,
    Phone TEXT,
    Password TEXT,
    Salt TEXT,
    IsVerified BOOLEAN,
    IsAdmin BOOLEAN
);

CREATE TABLE TwoFA (
    Email TEXT PRIMARY KEY,
    IsEnabled BOOLEAN,
    Secret TEXT
);

CREATE TABLE SecurityQuestions (
    Email TEXT PRIMARY KEY,
    IsEnabled BOOLEAN,
    Question1 TEXT,
    Answer1 TEXT,
    Question2 TEXT,
    Answer2 TEXT,
    Question3 TEXT,
    Answer3 TEXT
);

CREATE TABLE EvaluationRequests (
    EvaluationId INTEGER PRIMARY KEY AUTOINCREMENT,
    Email TEXT,
    Description TEXT,
    Contact TEXT,
    PhotoPath TEXT
);

CREATE TABLE LoginCounter (
    Email TEXT PRIMARY KEY,
    Attempts INTEGER
)