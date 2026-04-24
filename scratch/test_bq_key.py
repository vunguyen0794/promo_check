import os
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = r'D:\superset_auto\bq_key.json'

from google.cloud import bigquery

try:
    client = bigquery.Client(project='nimble-volt-459313-b8')
    # Test quyền jobs.create bằng cách chạy query đơn giản
    query = "SELECT CURRENT_DATE() as today, 'OK' as status"
    result = client.query(query).result()
    for row in result:
        print(f"BigQuery connection OK! today={row.today}, status={row.status}")
    print("Service account promo-v2 co quyen bigquery.jobs.create")
except Exception as e:
    print(f"FAILED: {e}")
