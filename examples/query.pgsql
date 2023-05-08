-- list image 
SELECT distinct image from vul order by 1;

-- list images with count and most recent records
SELECT 
    image, 
    count(*) records, 
    MIN(imported) min_updated,
    MAX(imported) max_updated
FROM vulns 
GROUP BY image 
ORDER BY 1;

-- list image versions 
SELECT 
    digest,
    count(*) records, 
    max(imported) updated
FROM vulns
WHERE image = 'docker.io/bitnami/mariadb'
GROUP BY digest
ORDER BY 3;

-- list image vulns per day 
SELECT 
    imported,
    count(*) records
FROM vulns
WHERE image = 'docker.io/bitnami/mariadb'
GROUP BY imported
ORDER BY 1 DESC;