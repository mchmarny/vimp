# vulctl builder 

## usage

```yaml
- id: sbom
  name: us-docker.pkg.dev/cloudy-build/vulctl/vulctl@sha256:d863f7bdf10e63f9f43298e73aad5886b87245827497b8333c038d6c1d2bdc58
  args:
  - -c
  - |
    --project $project
    --source $digest
    --format snyk
    --file path-tosnyk-report.json
```