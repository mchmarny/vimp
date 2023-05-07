# vimp on GCP

Aggregate all exposure data for images pushed into Artifact Registry and Container Registry in BigQuery using `vimp`.

## Setup

Start by [forking the `vimp` repo](https://github.com/mchmarny/vimp/fork) so that you can make changes. 

Next, make sure there are existing GitHub connections in Google Cloud Build:

> If not, this step will need to be created in UI.

```shell
gcloud alpha builds connections list --region $REGION
```

When done, export the following environment variables with your own values: 

```shell
# GCP project ID
export PROJECT_ID="your-gcp-project-id"
# GCP region where you want to run the scans
export REGION="us-west1"
# You can either enter your Snyk API token or remove the snyk-related steps from `scan.yaml` (grype and trivy do not require token)
export SNYK_TOKEN="your-snyk-token"
# you can leave this value as is, the dataset (`vimp`) and the table `vulnerabilities` will be created if they don't exist
export DATASET="bq://${PROJECT_ID}.vimp.vulnerabilities"
# GH_USER is the org/username where you forked the `vimp` repo 
export GH_USER="your-github-username"
```

Next, create a pub/sub topic (if one does not already exists):

```shell
gcloud pubsub topics create gcr --project $PROJECT_ID
```

Create a secret that will hold the snyk token:

```shell
gcloud secrets create vimp-snyk-token --replication-policy="automatic"
echo -n "${SNYK_TOKEN}" | gcloud secrets versions add vimp-snyk-token --data-file=- \
export SNYK_SECRET=$(gcloud secrets versions describe 1 --secret vimp-snyk-token --format="value(NAME)")
```

Finally, create a pub/sub trigger in GCB using the [provided build configurations file](scan-new-image.yaml). 

> More detail about the parameters used below [here](https://cloud.google.com/build/docs/automate-builds-pubsub-events):

```shell
gcloud alpha builds triggers create pubsub \
    --project=$PROJECT_ID \
    --region=$REGION \
    --name=scan-and-save-image-exposure-data \
    --topic=projects/$PROJECT_ID/topics/gcr \
    --build-config=cloud/gcp/scan.yaml \
    --substitutions=_DIGEST='$(body.message.data.digest)',_ACTION='$(body.message.data.action)',_SNYK_TOKEN=$SNYK_SECRET,_DATASET=$DATASET \
    --subscription-filter='_ACTION == "INSERT"' \
    --repo=https://www.github.com/$GH_USER/vimp \
    --repo-type=GITHUB \
    --branch=main
```

> Make sure that the service account which is used to execute the trigger (default `799736955886@cloudbuild.gserviceaccount.com`) has `roles/bigquery.dataEditor` and `roles/secretmanager.secretAccessor` roles.

## Test

The above trigger will fire automatically whenever a new image is pushed to either AR or GCR. You can also test it manually by coping existing image to any registry in the same project using `crane`: 

```shell
crane cp gcr.io/src-image gcr.io/target-image
```

The event published onto `gcr` topic will have the fully-qualified URI of the image (including digest). Example:

```json
{
    "message": {
        "data": {
            "action": "INSERT", 
            "digest": "us-west1-docker.pkg.dev/$PROJECT/repo/image@sha256:54bc0fead59f304f1727280c3b520aeea7b9e6fd405b7a6ee1dddc8d78044516", 
            "tag": "us-west1-docker.pkg.dev/$PROJECT/repo/image:latest"
        },
        "messageId": "7309198396944430",
        "publishTime": "2023-03-30T21:56:52.254Z"
    }
}
```

Cloud Build will automatically extract the payload (base64 encoded in the message), so in our workflow we can references the raw value (`body.message.data`). Using GCB substitutions then we can create the key environment variables. `_ACTION` is only used for filtering the appropriate messages, while the `_DIGEST` variable will have the fully-qualified URI of the image,including digest.

Using the digest, the [scan.yaml](scan.yaml) workflow will... you guest it, scan the image for vulnerabilities using three open source scanners: `grype`, `snyk`, and `trivy` and saves the resulting data into BigQuery table.

## Non-GCP Images 

You can also use the same workflow with non-AR/GCR images as long as the image is accessible to the service account under which your workflow is being executed. 

Start by creating new pub/sub topic which will be used to queue your images: 

> The topic name can be anything as long as it's the same in the topic and trigger create commands.

```shell
gcloud pubsub topics create image-queue --project $PROJECT_ID
```

Next create a trigger to process any new events on that queue with the same build config as above: 

```shell
gcloud alpha builds triggers create pubsub \
    --project=$PROJECT_ID \
    --region=$REGION \
    --name=scan-and-save-external-image-exposure-data \
    --topic=projects/$PROJECT_ID/topics/image-queue \
    --build-config=cloud/gcp/process.yaml \
    --substitutions=_DIGEST='$(body.message.data)',_SNYK_TOKEN=$SNYK_SECRET,_DATASET=$DATASET \
    --repo=https://www.github.com/$GH_USER/vimp \
    --repo-type=GITHUB \
    --branch=main
```

Now to process new image simply publish the image URI (with digest) to that topic:

```shell
gcloud pubsub topics publish image-queue \
    --message=https://docker.io/redis@sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448 \
    --project=$PROJECT_ID
```

## Schedule 

To schedule [image.txt](../../image.txt) to be queued for processing: 

```shell
gcloud beta builds triggers create manual \
    --name=queue-images \
    --project=$PROJECT_ID \
    --region=$REGION \
    --repo=https://www.github.com/$GH_USER/vimp \
    --repo-type=GITHUB \
    --branch=main \
    --build-config=cloud/gcp/queue.yaml
```

Next, capture the trigger ID:

```shell
export TRIGGER_ID=$(gcloud beta builds triggers describe \
    queue-images \
    --project=$PROJECT_ID \
    --region=$REGION \
    --format='value(id)')
```

You can run this trigger now manually, by invoking from `curl`. 

> This assumes that you have the necessary role to execute the build.

```shell
curl -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
     "https://cloudbuild.googleapis.com/v1/projects/$PROJECT_ID/locations/$REGION/triggers/$TRIGGER_ID:run"
```

That means we can now set it up as a Cloud Schedule, first, make sure the Cloud Build account has sufficient rights to execute the job:


```shell
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
    --role="roles/cloudbuild.builds.editor" \
    --condition=None
```

Finally, create the Cloud Scheduler job:

```shell
gcloud scheduler jobs create http queue-images-schedule \
    --http-method POST \
    --schedule='0 1 * * *' \
    --location=$REGION \
    --uri=https://cloudbuild.googleapis.com/v1/projects/$PROJECT_ID/locations/$REGION/triggers/$TRIGGER_ID:run \
    --oauth-service-account-email=$PROJECT_NUMBER-compute@developer.gserviceaccount.com \
    --oauth-token-scope=https://www.googleapis.com/auth/cloud-platform
```

Now everyday, at 1am UTC, the image will be rebuilt and the Cloud Workstation configuration updated with the latest image.

> See [examples/query.sql](../../examples/query.sql) for examples of SQL queries against the imported data.

## disclaimer

This is my personal project and it does not represent my employer. While I do my best to ensure that everything works, I take no responsibility for issues caused by this code.

