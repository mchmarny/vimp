CREATE TABLE IF NOT EXISTS vul (
    image text not null,
    digest text not null,
    source text not null,
    processed text not null,
    exposure text not null,
    package text not null,
    version text not null,
    severity text not null,
    score real not null,
    fixed boolean not null,
    primary key (image, digest, source, exposure, package, version)
);