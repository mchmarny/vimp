# vimp

Import CLI for data output from OSS vulnerability scanners. Extracts vulnerabilities from reports output by common OSS scanners and converts it into a generic format which then is saved into a target store. Useful for comparing data across multiple scanners.

## Usage

Given a container image digest:

```shell
export image="docker.io/redis@sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448"
```

Generate vulnerability report using one of the supported OSS scanners:

* [grype](https://github.com/anchore/grype) `grype --add-cpes-if-none -s AllLayers -o json --file report.json $image`
* [snyk](https://github.com/snyk/cli) `snyk container test --app-vulns --json-file-output=report.json $image`
* [trivy](https://github.com/aquasecurity/trivy) `trivy image --format json --output report.json $image`

Then, import that vulnerability data into one of the supported data stores:

```shell
vimp --source $image --file report.json --target bq://project.dataset.table
```

> Note, target table will be created if it does not exist.

The resulting schema in the target DB will look something like this (adjusted for DB-specific data types):

```sql
image       TEXT      NOT NULL
digest      TEXT      NOT NULL
source      TEXT      NOT NULL
processed   TIMESTAMP NOT NULL
cve         TEXT      NOT NULL
package     TEXT      NOT NULL
version     TEXT      NOT NULL
severity    TEXT      NOT NULL
score       FLOAT     NOT NULL
fixed       BOOL      NOT NULL
```

See [sql/query.sql](sql/query.sql) for examples of queries against the imported data. 

The imported data will look something like this: 

```json
[
    {
        "image": "https://docker.io/redis",
        "digest": "sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448",
        "source": "grype",
        "processed": "2023-04-04 13:15:22.410631 UTC",
        "cve": "CVE-2018-20860",
        "package": "libopenmpt0",
        "version": "0.3.6-1ubuntu0~18.04.1",
        "severity": "low",
        "score": "4.3",
        "fixed": "false"
    }
    ...
]
```

## Installation 

You can install `vimp` CLI using one of the following ways:

* [Go](#go)
* [Homebrew](#homebrew)
* [RHEL/CentOS](#rhelcentos)
* [Debian/Ubuntu](#debianubuntu)
* [Binary](#binary)

See the [release section](https://github.com/mchmarny/vimp/releases/latest) for `vimp` checksums and SBOMs.

### Go

If you have Go 1.17 or newer, you can install latest `vimp` using:

```shell
go install github.com/mchmarny/vimp@latest
```

### Homebrew

On Mac or Linux, you can install `vimp` with [Homebrew](https://brew.sh/):

```shell
brew tap mchmarny/vimp
brew install vimp
```

New release will be automatically picked up when you run `brew upgrade`

### RHEL/CentOS

```shell
rpm -ivh https://github.com/mchmarny/vimp/releases/download/v$VERSION/vimp-$VERSION_Linux-amd64.rpm
```

### Debian/Ubuntu

```shell
wget https://github.com/aquasecurity/vimp/releases/download/v$VERSION/vimp-$VERSION_Linux-amd64.deb
sudo dpkg -i vimp-$VERSION_Linux-64bit.deb
```

### Binary 

You can also download the [latest release](https://github.com/mchmarny/vimp/releases/latest) version of `vimp` for your operating system/architecture from [here](https://github.com/mchmarny/vimp/releases/latest). Put the binary somewhere in your $PATH, and make sure it has that executable bit.

> The official `vimp` releases include SBOMs

## Disclaimer

This is my personal project and it does not represent my employer. While I do my best to ensure that everything works, I take no responsibility for issues caused by this code.
