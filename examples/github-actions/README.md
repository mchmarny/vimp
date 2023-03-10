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

Below example, shows how to import vulnerabilities from previously generated report.

> Make sure to use the latest tag release (e.g. `v0.2.14`)

```yaml
uses: mchmarny/vulctl@v0.2.14
with:
  project: ${{ env.PROJECT_ID }}
  digest: ${{ steps.build.outputs.digest }}
  file: ${{ steps.scan.outputs.output }}
  format: ${{ steps.scan.outputs.format }}
```

> Fully working example can be found in [.github/workflows/import.yaml](../../.github/workflows/import.yaml).
