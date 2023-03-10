# vulctl as builder in Google Cloud Build (GCB)

To use `vulctl` in your GCB pipeline you will need to add the following step: 

```yaml
- id: import
name: us-west1-docker.pkg.dev/cloudy-build/vulctl/vulctl@sha256:b7a5357e60ec723159004d54d6973673d6a0125b0c5ebfa7005a82a3ad3116ce
waitFor:
- scan
args: ['import', '--project', '$PROJECT_ID', '--source', '${_IMAGE_URI}', '--file', 'report.json', '--format', 'grype']
```