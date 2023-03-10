# vulctl as builder in GitHub Actions (GHA)

In addition to being used as a CLI, `vulctl` can also be used as a builder.

## inputs

* `project` - (required) GCP Project ID
* `digest` - (required) Image digest
* `file` - (required) Path to the vulnerability file
* `format` - (required) Format of the vulnerability file

## outputs

none

## usage

```yaml
uses: actions/vulctl@main
with:
  project: cloudy-demo
  digest: ${{ env.IMAGE_DIGEST }}
  file: report.json
  format: snyk
```

> Fully working example can be found in [.github/workflows/on-push-import.yaml](../../.github/workflows/on-push-import.yaml).
