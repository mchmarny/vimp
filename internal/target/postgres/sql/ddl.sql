CREATE TABLE IF NOT EXISTS vulns (
    image text not null,
    digest text not null,
    source text not null,
    imported text not null,
    exposure text not null,
    package text not null,
    version text not null,
    severity text not null,
    score real not null,
    fixed boolean not null,
    processed timestamp not null,
    primary key (image, digest, source, imported, exposure, package, version)
);