[![](https://github.com/mchmarny/vulctl/actions/workflows/on-push.yaml/badge.svg?branch=main)](https://github.com/mchmarny/vulctl/actions/workflows/on-push.yaml)
[![](https://github.com/mchmarny/vulctl/actions/workflows/on-tag.yaml/badge.svg)](https://github.com/mchmarny/vulctl/actions/workflows/on-tag.yaml)
[![](https://codecov.io/gh/mchmarny/vulctl/branch/main/graph/badge.svg?token=9HLYDZZADN)](https://codecov.io/gh/mchmarny/vulctl)
[![version](https://img.shields.io/github/release/mchmarny/vulctl.svg?label=version)](https://github.com/mchmarny/vulctl/releases/latest)
[![](https://img.shields.io/github/go-mod/go-version/mchmarny/vulctl.svg?label=go)](https://github.com/mchmarny/vulctl)
[![](https://goreportcard.com/badge/github.com/mchmarny/vulctl)](https://goreportcard.com/report/github.com/mchmarny/vulctl)

# vulctl

Vulnerability management tool


## CLI Installation 

You can install `vulctl` CLI using one of the following ways:

* [Homebrew](#homebrew)
* [RHEL/CentOS](#rhelcentos)
* [Debian/Ubuntu](#debianubuntu)
* [Go](#go)
* [Binary](#binary)

See the [release section](https://github.com/mchmarny/vulctl/releases/latest) for `vulctl` checksums and SBOMs.

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

## Go

If you have Go 1.17 or newer, you can install latest `vulctl` using:

```shell
go install github.com/mchmarny/vulctl/cmd/vulctl@latest
```

## Binary 

You can also download the [latest release](https://github.com/mchmarny/vulctl/releases/latest) version of `vulctl` for your operating system/architecture from [here](https://github.com/mchmarny/vulctl/releases/latest). Put the binary somewhere in your $PATH, and make sure it has that executable bit.

> The official `vulctl` releases include SBOMs

## Prerequisites 

Since you are interested in `vulctl`, you probably already have GCP account and project. If not, you learn about creating and managing projects [here](https://cloud.google.com/resource-manager/docs/creating-managing-projects). The other prerequisites include:

### APIs

`vulctl` also depends on a few GCP service APIs. To enable these, run:

```shell
gcloud services enable \
  artifactregistry.googleapis.com \
  containeranalysis.googleapis.com \
  containerregistry.googleapis.com
```

### Roles

Make sure you have the following Identity and Access Management (IAM) roles in each project: 

> Learn how to grant multiple IAM roles to a user [here](https://cloud.google.com/iam/docs/granting-changing-revoking-access#multiple-roles)

```shell
roles/containeranalysis.occurrences.editor
roles/containeranalysis.notes.editor
```

If you experience any issues, you can see the project level policy using following command:

```shell
gcloud projects get-iam-policy $PROJECT_ID --format=json > policy.json
```

## Disclaimer

This is my personal project and it does not represent my employer. While I do my best to ensure that everything works, I take no responsibility for issues caused by this code.
