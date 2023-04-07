# vimp

Compare data from multiple vulnerability scanners to get a more complete picture of potential exposures. 

`vimp` CLI currently supports output from common oepn source vulnerability scanners like [grype](https://github.com/anchore/grype), [snyk](https://github.com/snyk/cli), and [trivy](https://github.com/aquasecurity/trivy). The CLI also comes with an embedded data store (`sqlite`) and support for other databases, like [BigQuery](https://cloud.google.com/bigquery). Alternatively, `vimp` can also output to local file (`JSON` or `CVS`) or `stdout`.

## Usage

Start by using a container image, tor example, the official Redis image in Docker Hub:

```shell
export image="docker.io/redis@sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448"
```

`vimp` currently recognizes the output from the following OSS scanners/formats:

*  `grype --add-cpes-if-none -s AllLayers -o json --file report.json $image`
*  `snyk container test --app-vulns --json-file-output=report.json $image`
*  `trivy image --format json --output report.json $image`

You can either import the resulting reports from any of the above commands into the local data store:

```shell
vimp import --source $image --file report.json
```

Or, omit the `--file` flag all together and `vimp` will automatically scan and import the provided image with any of the installed scanners:

```shell
vimp import --source $image
```

By default, `vimp` will store the imported data in Sqlite DB (`.vimp.db`) in your home directory. You can use the `--target` flag to save it to another location (e.g. `sqlite://data/vimp.db`). Find all the scanner and target data store options using `vimp import -h`.

The output for the above command should look something like this: 

```shell
vimp import --source docker.io/redis@sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448
INF v0.5.3
INF scanning image docker.io/redis@sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448
INF grype scan completed: grype-110213000.json
INF found 83 unique vulnerabilities
INF snyk scan completed: snyk-255733000.json
INF found 78 unique vulnerabilities
INF trivy scan completed: trivy-658830000.json
INF found 79 unique vulnerabilities
INF importing: digest=sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448 image=https://docker.io/redis target=sqlite://.vimp.db
```

Once you data is imported, you can then run queries against that data. The default query against the same data will provide summary of all the data in your store: 

```shell
vimp query
```

> Note, by default, `vimp` will query (`.vimp.db`) in your home directory. You can target different database using the `--target` flag (e.g. `sqlite://data/vimp.db`).

After importing data for one image from three sources the response will look something like this: 

```json
INF found 1 records
{
  "https://docker.io/redis": {
    "versions": {
      "sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448": {
        "exposures": 240,
        "sources": 3,
        "packages": 73,
        "high_score": 10,
        "first_discovered": "2023-04-05T19:29:16Z",
        "last_discovered": "2023-04-05T19:41:11Z"
      }
    }
  }
}
```

To dig deeper into the data for that image, you can list all the vulnerabilities found that image across all of the sources: 

```shell
vimp query --image https://docker.io/redis \
           --digest sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448
```

The results for that query should look something like this: 

> Notice the differences in `severity` and `score` reported by the different scanners:

```json
{
  "image": "https://docker.io/redis",
  "digest": "sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448",
  "exposures": {
    "CVE-2005-2541": [
      {
        "source": "grype",
        "severity": "negligible",
        "score": 10,
        "last_discovered": "2023-04-05T19:40:42Z"
      },
      {
        "source": "snyk",
        "severity": "low",
        "score": 9.8,
        "last_discovered": "2023-04-05T19:29:16Z"
      },
      {
        "source": "trivy",
        "severity": "low",
        "score": 10,
        "last_discovered": "2023-04-05T19:41:11Z"
      }
    ],
    "CVE-2007-5686": [
      {
        "source": "grype",
        "severity": "negligible",
        "score": 4.9,
        "last_discovered": "2023-04-05T19:40:42Z"
      },
      ...
    ],
  }
}
```

> There will be a lot of commonalities in the data returned by each one of the scanners. You can append the `--diffs-only` flag to highlight only the data where the exposures are not the same across all of the sources. 

To drill into the packages impacted by each vulnerabilities you can use the additional `--exposure` flag: 

```shell
vimp query --image https://docker.io/redis \
           --digest sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448 \
           --exposure CVE-2005-2541
```

The result should look something like this: 

```json
INF found 3 records
{
  "image": "https://docker.io/redis",
  "digest": "sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448",
  "exposure": "CVE-2005-2541",
  "packages": [
    {
      "source": "grype",
      "package": "tar",
      "version": "1.34+dfsg-1",
      "severity": "negligible",
      "score": 10,
      "last_discovered": "2023-04-05T19:40:42Z"
    },
    {
      "source": "snyk",
      "package": "tar",
      "version": "1.34+dfsg-1",
      "severity": "low",
      "score": 9.8,
      "last_discovered": "2023-04-05T19:29:16Z"
    },
    {
      "source": "trivy",
      "package": "tar",
      "version": "1.34+dfsg-1",
      "severity": "low",
      "score": 10,
      "last_discovered": "2023-04-05T19:41:11Z"
    }
  ]
}
```

## Data Store

The schema created by `vimp` in the target DB will look something like this (adjusted for DB-specific data types):

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

> See https://github.com/mchmarny/artifact-events for how to set up `vimp` as an import for all new images in GCR or AR on GCP.

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
