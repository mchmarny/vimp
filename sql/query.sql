-- list distinct images
SELECT DISTINCT image FROM `cloudy-demos.artifact.vul` ORDER BY 1

-- list versions a given image
SELECT DISTINCT digest
FROM `cloudy-demos.artifact.vul`
WHERE image = 'https://us-west1-docker.pkg.dev/cloudy-demos/events/artifact1'


-- list vulnerabilities for a given image
SELECT
    cve,
    source,
    severity,
    score,
    MAX(processed) last_processed
FROM `cloudy-demos.artifact.vul`
WHERE image = 'https://us-west1-docker.pkg.dev/cloudy-demos/events/artifact1'
AND digest = 'sha256:14dd03939d2d840d7375f394b45d340d95fba8e25070612ac2883eacd7f93a55'
GROUP BY cve, source, severity, score
ORDER BY 1, 2

-- list packages for a given image cve
SELECT
    source,
    package,
    version,
    severity,
    score,
    MAX(processed) last_processed
FROM `cloudy-demos.artifact.vul`
WHERE image = 'https://us-west1-docker.pkg.dev/cloudy-demos/events/artifact1'
AND digest = 'sha256:14dd03939d2d840d7375f394b45d340d95fba8e25070612ac2883eacd7f93a55'
AND cve = 'CVE-2009-5155'
GROUP BY source, package, version, severity, score
ORDER BY 1, 2, 3
