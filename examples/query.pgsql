-- list image 
SELECT distinct image from vul order by 1;

-- list images with count and most recent records
SELECT 
    image, 
    count(*) records, 
    DATE(MIN(processed)) min_updated,
    DATE(MAX(processed)) max_updated
FROM vul 
GROUP BY image 
ORDER BY 1;

-- list image versions 
SELECT 
    digest,
    count(*) records, 
    DATE(max(processed)) updated
FROM vul
WHERE image = 'docker.io/bitnami/mariadb'
GROUP BY digest
ORDER BY 3;

-- list image vulns per day 
SELECT 
    DATE(processed) updated,
    count(*) records
FROM vul
WHERE image = 'docker.io/bitnami/mariadb'
GROUP BY DATE(processed)
ORDER BY 1;