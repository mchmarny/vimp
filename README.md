[![](https://github.com/mchmarny/vulctl/actions/workflows/on-push.yaml/badge.svg?branch=main)](https://github.com/mchmarny/vulctl/actions/workflows/on-push.yaml)
[![tag-release](https://github.com/mchmarny/vulctl/actions/workflows/on-tag.yaml/badge.svg?branch=main)](https://github.com/mchmarny/vulctl/actions/workflows/on-tag.yaml)
[![](https://codecov.io/gh/mchmarny/vulctl/branch/main/graph/badge.svg?token=9HLYDZZADN)](https://codecov.io/gh/mchmarny/vulctl)
[![version](https://img.shields.io/github/release/mchmarny/vulctl.svg?label=version)](https://github.com/mchmarny/vulctl/releases/latest)
[![](https://img.shields.io/github/go-mod/go-version/mchmarny/vulctl.svg?label=go)](https://github.com/mchmarny/vulctl)
[![](https://goreportcard.com/badge/github.com/mchmarny/vulctl)](https://goreportcard.com/report/github.com/mchmarny/vulctl)

# vulctl

Vulnerability scanners result processing tool. Generalizes vulnerability reports from common OSS scanners into a generic format which then can be used to compare data across scanners or persist in database. 

```shell
export image="docker.io/redis@sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448"
```

The currently supported scanners/formats include:

* [grype](https://github.com/anchore/grype) `grype --add-cpes-if-none -s AllLayers -o json --file report.json $image`
* [snyk](https://github.com/snyk/cli) `snyk container test --app-vulns --json-file-output=report.json $image`
* [trivy](https://github.com/aquasecurity/trivy) `trivy image --format json --output report.json $image`

Then, to process the vulnerability report output from `grype`:

```shell
vulctl --source $image --file report.json --format grype
```

The resulting file or stdout output will look something like this:

```json
{
  "uri": "https://docker.io/redis",
  "digest": "sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448",
  "processed_at": "2023-04-01T21:53:11.616Z",
  "record_count": 82,
  "vulnerabilities": [
    {
      "id": "GHSA-vpvm-3wq2-2wvm",
      "package": "github.com/opencontainers/runc",
      "version": "v1.1.0",
      "severity": "high",
      "score": 7,
      "fixed": true
    },
    {
      "id": "CVE-2023-0466",
      "package": "libssl1.1",
      "version": "1.1.1n-0+deb11u4",
      "severity": "unknown",
      "score": 0,
      "fixed": false
    },
    {
      "id": "CVE-2022-1304",
      "package": "e2fsprogs",
      "version": "1.46.2-2",
      "severity": "high",
      "score": 6.8,
      "fixed": false
    },
    ...
  ]
}
```


## Installation 

You can install `vulctl` CLI using one of the following ways:

* [Go](#go)
* [Homebrew](#homebrew)
* [RHEL/CentOS](#rhelcentos)
* [Debian/Ubuntu](#debianubuntu)
* [Binary](#binary)

See the [release section](https://github.com/mchmarny/vulctl/releases/latest) for `vulctl` checksums and SBOMs.

## Go

If you have Go 1.17 or newer, you can install latest `vulctl` using:

```shell
go install github.com/mchmarny/vulctl/cmd/vulctl@latest
```

## Homebrew

On Mac or Linux, you can install `vulctl` with [Homebrew](https://brew.sh/):

```shell
brew tap mchmarny/vulctl
brew install vulctl
```

New release will be automatically picked up when you run `brew upgrade`

## RHEL/CentOS

```shell
rpm -ivh https://github.com/mchmarny/vulctl/releases/download/v$VERSION/vulctl-$VERSION_Linux-amd64.rpm
```

## Debian/Ubuntu

```shell
wget https://github.com/aquasecurity/vulctl/releases/download/v$VERSION/vulctl-$VERSION_Linux-amd64.deb
sudo dpkg -i vulctl-$VERSION_Linux-64bit.deb
```

## Binary 

You can also download the [latest release](https://github.com/mchmarny/vulctl/releases/latest) version of `vulctl` for your operating system/architecture from [here](https://github.com/mchmarny/vulctl/releases/latest). Put the binary somewhere in your $PATH, and make sure it has that executable bit.

> The official `vulctl` releases include SBOMs

## Disclaimer

This is my personal project and it does not represent my employer. While I do my best to ensure that everything works, I take no responsibility for issues caused by this code.
