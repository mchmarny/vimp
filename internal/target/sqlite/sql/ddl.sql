CREATE TABLE IF NOT EXISTS vul (
    image TEXT NOT NULL,
    digest TEXT NOT NULL,
    source TEXT NOT NULL,
    processed TEXT NOT NULL,
    cve TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    severity TEXT NOT NULL,
    score REAL NOT NULL,
    fixed NUMERIC NOT NULL,
    PRIMARY KEY (image, digest, source)
);