# Amazon Security Lake bridge

> **Unofficial, and tested against documented response shapes only.** This bridge has not run against a real Security Lake, Athena workgroup or Sophos NG-SIEM HTTP Ingest integration. Its unit tests use a local mock server built from the Athena and S3 API references and the Athena UNLOAD docs. Run it with `--dry-run` first and check what it would send.

Amazon Security Lake keeps its records in the Open Cybersecurity Schema Framework (OCSF) as Apache Parquet objects in S3, and Sophos NG-SIEM can't read Parquet. This script has Amazon Athena write each new window of a Security Lake table out as JSON Lines, with `UNLOAD`, then reads those files and sends each record as one JSON line to a Sophos NG-SIEM HTTP Ingest integration. It adds `"security_lake_record": "ocsf"` and `"security_lake_table"` in front of each record, and the library parsers in `parsers/amazon-web-services/amazon-security-lake` normalize them. Sophos Fusion has no Security Lake integration.

| Data | Request | Signed for |
| --- | --- | --- |
| Each table's columns and their types | Athena `StartQueryExecution` with `SELECT column_name, data_type FROM information_schema.columns ...`, then `GetQueryExecution` and `GetQueryResults` | `athena` |
| The records of each new window | Athena `StartQueryExecution` with `UNLOAD (SELECT ...) TO 's3://...' WITH (format = 'JSON')`, then `GetQueryExecution` until it ends | `athena` |
| The files `UNLOAD` wrote | S3 `GET` of the query's data manifest, then of each gzip JSON Lines file it lists, 8 MB at a time | `s3` |

Requests are signed with AWS Signature Version 4. Python 3.9 or later, standard library only. One file: `security_lake_bridge.py`.

## Before you start

**Sophos Fusion.** Go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Name it and copy the Integration Key and URL; they are shown once. Add the parsers from `parsers/amazon-web-services/amazon-security-lake` under Security Operations > Integrations > Custom Parsers, parent first, and use Run Test with your own records before you turn them on.

**AWS.**

1. Security Lake collects your sources with source version 2 (OCSF 1.1.0), whose tables are `amazon_security_lake_table_<region>_<source>_2_0` in the Glue database `amazon_security_lake_glue_db_<region>`, with the Region's hyphens as underscores. The bridge reads source version 1 and custom source tables too, by `time` within their `eventday` partitions, but the library parsers are written for source version 2.
2. Give the bridge query access. In the Security Lake account, grant its IAM principal SELECT and DESCRIBE on the tables, and DESCRIBE on the database, in AWS Lake Formation. From another account, create a Security Lake query subscriber, accept the AWS RAM share, create resource links to the shared database and tables, grant the same on the links, and set `SECURITY_LAKE_DATABASE` and `SECURITY_LAKE_TABLES` to the links' names.
3. Make an S3 bucket in the same Region for the bridge, with a lifecycle rule that expires objects under its prefix after a day. `UNLOAD` writes only to an empty location, so the bridge gives each query its own folder under `ATHENA_UNLOAD_LOCATION` and leaves the files for the lifecycle rule to remove.
4. Use an Athena workgroup on engine version 3 that saves query results to S3 (not managed query results), since the bridge reads each query's data manifest from there. Set the workgroup's result location, or `ATHENA_OUTPUT_LOCATION`, to the same bucket.
5. Give the bridge's IAM principal a policy that allows `athena:StartQueryExecution`, `athena:GetQueryExecution`, `athena:GetQueryResults` and `athena:StopQueryExecution` on the workgroup; `glue:GetDatabase`, `glue:GetTable`, `glue:GetTables` and `glue:GetPartitions` on the catalog, the database and the tables (and the resource links); `lakeformation:GetDataAccess`; and on the bridge's bucket and prefix `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`, `s3:GetBucketLocation`, `s3:AbortMultipartUpload` and `s3:ListMultipartUploadParts`. Add `kms:Decrypt` and `kms:GenerateDataKey` for any KMS key that encrypts the Security Lake data or the bridge's bucket. The bridge needs no other access: it changes nothing in Security Lake.

Athena bills each query by the data it scans, with a minimum per query. Each run makes two queries for each table: the column list, and the `UNLOAD` of the window, which reads only the days of the window.

## Configuration

Everything comes from environment variables. Keep the AWS keys and the HTTP Ingest key in a secrets manager or an environment file only the bridge's account can read.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NGSIEM_INGEST_URL` | none | The HTTP Ingest URL from Sophos Fusion. Required unless `--dry-run`. |
| `NGSIEM_INGEST_KEY` | none | The HTTP Ingest Integration Key, sent as `Authorization: Bearer`. Required unless `--dry-run`. |
| `AWS_ACCESS_KEY_ID` | none | The access key of the bridge's IAM principal. |
| `AWS_SECRET_ACCESS_KEY` | none | Its secret access key. |
| `AWS_SESSION_TOKEN` | none | The session token, with temporary keys. |
| `AWS_REGION` | none | The Region of the tables, Athena and the bridge's bucket, such as `ap-southeast-2`. `AWS_DEFAULT_REGION` works too. |
| `SECURITY_LAKE_SOURCES` | `cloud_trail_mgmt,route53,vpc_flow,sh_findings` | The source version 2 tables to read, by source: `cloud_trail_mgmt`, `lambda_execution`, `s3_data`, `route53`, `vpc_flow`, `sh_findings`, `eks_audit` and `waf`, comma separated. |
| `SECURITY_LAKE_TABLES` | none | Table names to read instead, comma separated, such as a query subscriber's resource links. |
| `SECURITY_LAKE_DATABASE` | `amazon_security_lake_glue_db_<region>` | The Glue database, or the resource link to it. |
| `ATHENA_WORKGROUP` | `primary` | The Athena workgroup. |
| `ATHENA_UNLOAD_LOCATION` | none | Required. The S3 location where Athena writes the JSON files, such as `s3://example-bucket/security-lake-bridge/`. |
| `ATHENA_OUTPUT_LOCATION` | none | The S3 location for query results and manifests. Empty uses the workgroup's. |
| `ATHENA_QUERY_TIMEOUT` | `900` | Seconds a query may run, 30 to 86400, before the bridge stops it. |
| `AWS_ENDPOINT_URL_ATHENA` | none | Another Athena endpoint, such as a VPC endpoint. |
| `AWS_ENDPOINT_URL_S3` | none | Another S3 endpoint, such as a VPC endpoint, which gets the bucket in the path. |
| `BRIDGE_STATE_FILE` | `security_lake_state.json` | Each table's last window end and the records sent within the overlap. |
| `BRIDGE_LOOKBACK_HOURS` | `24` | How far back the first run starts. |
| `BRIDGE_DELAY_SECONDS` | `900` | How long before now each window ends, up to 86400, since Security Lake adds records some minutes after they happen. |
| `BRIDGE_OVERLAP_SECONDS` | `2700` | How far before the last window's end each run reads again, for records that reached Security Lake late. Repeats are dropped. |
| `BRIDGE_BATCH_BYTES` | `100000` | Batch size before compression. Sophos recommends about 100 KB per request. |
| `BRIDGE_GZIP` | `1` | Send `Content-Encoding: gzip`. |
| `BRIDGE_HTTP_TIMEOUT` | `60` | Seconds per request. |
| `BRIDGE_DRY_RUN` | `0` | Same as `--dry-run`. |

Only https URLs are accepted, except plain http to this machine for testing.

## Run it

```bash
python3 security_lake_bridge.py --dry-run         # print the NDJSON it would send; sends and saves nothing
python3 security_lake_bridge.py                   # one pass, for cron or a systemd timer
python3 security_lake_bridge.py --interval 900    # keep polling every 15 minutes
```

A dry run still runs the Athena queries, which are billed and write their files to `ATHENA_UNLOAD_LOCATION`.

Exit code 0 means every table was read and sent. On an error the bridge logs it with the HTTP status or Athena's reason, stops, and leaves the window where it was, so the next run reads the same records again and drops the ones it already sent. A response over 64 MB, or a record over 16 MB once unpacked, also stops the run, so a broken or hostile endpoint can't use up memory. With `--interval`, any other unexpected error is logged with the line it came from, never a key, and the bridge tries again at the next interval.
With `--interval`, a network error that outlasts the retries is logged, naming only the host, and the bridge tries again at the next interval; a configuration or key error still stops it.
A 408, 429, 500, 502, 503 or 504 that outlasts the retries, a read timeout, and an answer cut off partway count as network errors too; a host name that doesn't resolve stops the bridge if no run has worked yet, since it is most likely a mistyped URL. So do a query Athena stopped as retryable and a query that ran past `ATHENA_QUERY_TIMEOUT`, which the bridge stops.
An answer that ends short of its Content-Length counts as cut off partway too, so nothing from it is sent or saved. A 501 or 505 stops the bridge, since a retry won't change it, with a message that says what the code means. A user name or password before the host in a URL setting (`user:pass@`) stops the bridge at startup, since it can't use them.

As a systemd service that polls, with the variables in `/etc/amazon-security-lake.env` (owned by root, mode 600):

```ini
[Unit]
Description=Amazon Security Lake bridge to Sophos NG-SIEM HTTP Ingest
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/amazon-security-lake/security_lake_bridge.py --interval 900
EnvironmentFile=/etc/amazon-security-lake.env
DynamicUser=yes
StateDirectory=amazon-security-lake
WorkingDirectory=/var/lib/amazon-security-lake
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

`Restart=on-failure` starts the bridge again a minute after it stops, for example when it started before the network was up: a host name that doesn't resolve stops it if no run has worked yet.

## How it reads Security Lake

- Each run reads each table from the end of its last window, less `BRIDGE_OVERLAP_SECONDS`, to `BRIDGE_DELAY_SECONDS` before now. The first run starts `BRIDGE_LOOKBACK_HOURS` back.
- It first asks Athena for the table's columns, from `information_schema.columns`. Athena's JSON writer can't write a timestamp with a time zone, which the `*_dt` columns of source version 2 hold, so each column with a timestamp in it, at any depth, is cast to its own type with the timestamps as text, such as `2026-10-20 01:12:40.000 UTC`. Every other column, and every OCSF time in milliseconds, is written as it is.
- Then it runs `UNLOAD (SELECT <every column> FROM "<database>"."<table>" WHERE time_dt >= TIMESTAMP '<start>' AND time_dt < TIMESTAMP '<end>') TO 's3://<bucket>/<prefix>/<day>/<random>/' WITH (format = 'JSON')`. Source version 2 tables are partitioned on `time_dt`, so this reads only the window's days. A table without `time_dt` is read by `time`, in milliseconds, within its `eventday` partitions.
- It checks the query every 1 to 10 seconds until it ends, then reads the query's data manifest and each file it lists, and only files under the folder it gave the query. Each file is gzip JSON Lines, read 8 MB at a time.
- Every request carries a `ClientRequestToken`, so a retried start can't run a query twice. A query that runs past `ATHENA_QUERY_TIMEOUT` is stopped with `StopQueryExecution`.
- A Security Hub finding keeps its `uid` when it changes, so the bridge knows each record by a hash of all of it, and drops a record it sent before within the overlap. A window's end is saved only after every file of it was sent, and never past the time of the run.
- The bridge waits and retries 408, 429, 500, 502, 503 and 504, and Athena's throttling answers (HTTP 400 `TooManyRequestsException` or `ThrottlingException`), up to 6 times, honoring `Retry-After` up to 5 minutes. Keys AWS refuses (`UnrecognizedClientException`, `InvalidSignatureException`, an expired token) stop the bridge without AWS's message, which can quote the signed request. A 403 or `AccessDeniedException` names the permissions above. A query Athena fails shows Athena's reason. HTTP Ingest 400, 401, 403 and 413 are not retried. A redirect from Athena, S3 or HTTP Ingest is refused, not followed, so no signed request goes to another URL, and the run stops with an error that says so.

HTTP Ingest delivers at least once. A crash between sending a batch and saving the state can send that batch again; HTTP Ingest does not remove duplicates.
If HTTP Ingest's answer to a batch is cut off partway, the bridge sends that batch again, so it can arrive twice.

The bridge never logs the AWS keys, the session token, the HTTP Ingest key, or the HTTP Ingest URL path.

## Tests

```bash
python3 -m unittest discover -s bridges/amazon-security-lake -p 'test_*.py' -v
```

The tests start a local mock of Athena and S3, built from the documented shapes, and of HTTP Ingest. The mock checks each request's signature, answers the column list over several pages, writes a query's rows as gzip JSON Lines files and a data manifest the way `UNLOAD` does, refuses a location that isn't empty, and fails an `UNLOAD` that would write a timestamp with a time zone. The tests check the signature against AWS's worked example, the column casts at any depth, the time filters, polling, failed, retryable, throttled and timed-out queries, files read in parts and in several gzip members, damaged files, the manifest check, windows, overlaps and repeats, that a window ends only after HTTP Ingest accepted it, refused keys and permissions, S3 errors, dry-run, retries, batching and gzip, refused redirects, the response size cap, settings, and that no secret reaches the log.

## References

- Security Lake source version 2 tables, partitions and example queries: https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-query-examples2.html
- Security Lake and OCSF (sources and the OCSF classes they map to): https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html
- Security Lake query subscribers (Lake Formation, AWS RAM, resource links): https://docs.aws.amazon.com/security-lake/latest/userguide/create-query-subscriber-procedures.html
- Athena UNLOAD (formats, empty location, manifest): https://docs.aws.amazon.com/athena/latest/ug/unload.html
- Athena query output files and the data manifest: https://docs.aws.amazon.com/athena/latest/ug/querying-finding-output-files.html
- Athena StartQueryExecution (ClientRequestToken), GetQueryExecution, GetQueryResults and StopQueryExecution: https://docs.aws.amazon.com/athena/latest/APIReference/API_StartQueryExecution.html
- Athena Iceberg tables (engine version 3, data types): https://docs.aws.amazon.com/athena/latest/ug/querying-iceberg.html
- AWS Signature Version 4: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
- S3 GetObject (Range, errors): https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
- Sophos Fusion HTTP Ingest setup: https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/Custom/HTTPIngest/Setup/index.html
- HTTP Ingest API contract, in the Taegis docs for the same platform: https://docs.taegis.secureworks.com/apis/using_http_ingest_api/
