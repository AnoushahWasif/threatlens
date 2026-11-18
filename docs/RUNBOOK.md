# Runbook: what to do when an alarm fires

There's one section per alarm in `infra/modules/monitoring` (decision 74). Each says what the alarm means, what to look at first, and what usually fixes it. Every alarm also emails when it clears, so a short spike that sorts itself out sends two emails, a few minutes apart.

**Nothing is deployed yet.** These steps follow the code and the Terraform, and they need checking against the real thing after the first deploy (day 17).

## Before you start

- **Account and region:** run every command with the ThreatLens account's profile and `--region eu-west-2`, never the default profile.
- **Log groups:**
  - `/aws/lambda/threatlens-api`: one JSON line per request, plus errors.
  - `/aws/lambda/threatlens-worker`: one line per scan outcome, plus errors.
  - `/aws/apigateway/threatlens-api`: API Gateway access logs. These include requests that never reached the Lambda, such as ones refused by the JWT check or the throttle.
- **Request ids:** every app log line has a `request_id`, and a scan's lines carry the id of the upload that started it. So one id finds everything about one request.
- **What the logs never hold:** tokens, file contents, user text or exception messages (decision 73). Exceptions are logged by class and frames. If a frame doesn't explain it, reproduce the problem locally.
- **Dashboard:** the `dashboard` output of `terraform output` has the same metrics side by side.

To find what a request id did, run this in CloudWatch Logs Insights over all three log groups:

```
fields @timestamp, @log, message, status, route, error
| filter request_id = "<id>"
| sort @timestamp asc
```

## threatlens-api-5xx

**Means:** API Gateway returned 5 or more 5xx responses in 5 minutes.

**First look:**

```
fields @timestamp, route, status, integrationErr
| filter status >= 500
| stats count() by route, status, integrationErr
```

(on `/aws/apigateway/threatlens-api`)

**Usually:**
- **`503` with `storage_busy` or `storage_unavailable`:** DynamoDB is throttling or down. The app sends `Retry-After`, and on-demand tables throttle only on sudden big jumps, so this normally clears by itself. Check the AWS Health Dashboard if it doesn't.
- **`503` with `queue_unavailable`:** SQS refused a send. Check the queue still exists and that the queue policy still allows the API role (`OnlyTheApiSends`).
- **`502 llm_unavailable` on the draft route:** the LLM provider is down, or its key is missing or revoked. Drafting fails closed, and nothing else is affected. (These count as 5xx too.)
- **`500`:** an unhandled error. `threatlens-unhandled-errors` will fire too; see that section.
- **`integrationErr` set:** the Lambda didn't answer (timeout, crash or throttle). `threatlens-api-errors` fires too.

## threatlens-api-latency

**Means:** p95 latency stayed above the limit (`latency_p95_ms`) for 15 minutes.

**First look:** the slowest routes, on `/aws/lambda/threatlens-api`:

```
fields route, duration_ms
| filter message = "request"
| stats pct(duration_ms, 95) as p95, count() as n by route
| sort p95 desc
```

**Usually:**
- **Only the draft route:** the LLM is slow. That's expected up to its timeout, and it doesn't hold anything else up.
- **Everything, with low traffic:** cold starts. Compare `Init Duration` in the `REPORT` lines. If that's the cause, it's a cost decision (provisioned concurrency), not a bug.
- **Everything, with high traffic:** DynamoDB or Cognito key fetches. Look at the X-Ray service map for the slow segment.

## threatlens-dead-letters

**Means:** at least one scan message is in `threatlens-scans-dead`. The worker received it 5 times and never finished it. That's a crash or timeout the worker didn't catch itself, since its own failures stop at 3 attempts and mark the scan failed.

**First look:**
- `threatlens-worker-errors` probably fired earlier. Its `REPORT` lines show whether it was a timeout (`Status: timeout`) or a crash.
- Read the message without deleting it:

  ```
  aws sqs receive-message --queue-url <dead-letter queue url> --visibility-timeout 0 --max-number-of-messages 1
  ```

  It holds ids only (owner, project and scan), plus the request id. Search the worker log for that `scan_id`.

**Usually:**
- **A timeout on a huge file**, at 600 s (decision 61). The 1 MB and 20,000-package limits are meant to stop that, so it's a bug worth reproducing locally.
- **A crash in a parser.** Reproduce it locally with the same file type.

**When fixed:** move the messages back to the scan queue:

```
aws sqs start-message-move-task --source-arn <dead-letter queue arn>
```

Scans that are already done or failed are skipped (decision 43). Messages kept longer than 14 days are lost, but the user can upload the file again.

## threatlens-scans-stuck

**Means:** the oldest message in the scan queue has waited over 3 hours, so scans aren't being taken.

**First look:**
- Does the worker's SQS trigger still exist and show `Enabled`? `aws lambda list-event-source-mappings --function-name threatlens-worker`
- Is the worker throttled? Look at the Lambda `Throttles` metric and the account's concurrency.
- Are scans failing and being retried? A retry waits out the queue's one-hour visibility timeout. Two retries are about 2 hours, so a third pushes a message over the line.

**Usually:**
- **The trigger was disabled** (by hand, or by a deploy). Turn it back on.
- **One very slow scan:** at most 2 scans run at once (decision 61). Raise `maximum_concurrency` only knowing that OSV, EPSS and KEV take the extra load.

## threatlens-api-errors and threatlens-worker-errors

**Means:** a Lambda invocation crashed or timed out. That's an error Lambda itself counts, not a 4xx or 5xx the app chose.

**First look**, on the function's log group:

```
fields @timestamp, @message
| filter @message like /Task timed out|Runtime.ExitError|error/
| sort @timestamp desc
| limit 20
```

**Usually:**
- **API timeout at 29 s on the draft route:** a known gap (issue #51). The LLM client allows 90 s per try, but the Lambda stops at 29 s, so a long draft dies as a timeout. Its cost has already counted toward the hourly cap, and its lease runs out after 6 minutes.
- **API timeout at 29 s anywhere else:** something blocked. OSV, EPSS and GitHub calls have their own timeouts (10 s by default, 30 s for the KEV download), so look for a call without one in X-Ray.
- **Out of memory** (`Runtime.ExitError`, with `Max Memory Used` at the limit): a big upload parsed in memory. Raise `memory` in `infra/modules/api/main.tf` and check the upload limits held.
- **Import error after a deploy:** the zip is missing a package. The CI `lambda-package` job should have caught it, so roll back to the previous zip.

## threatlens-unhandled-errors

**Means:** the API logged `unhandled error` at least once in 5 minutes. A request hit an exception no route handles, and the user got a plain 500 with a request id.

**First look**, on `/aws/lambda/threatlens-api`:

```
fields @timestamp, request_id, error, traceback
| filter message = "unhandled error"
| sort @timestamp desc
| limit 20
```

`error` is the exception class. `traceback` has file, line and function names without messages (decision 73).

**Usually:** a bug. Reproduce it from the frames with a test, fix it, and deploy. If a user reports a 500, the request id they saw is the `request_id` here.

## threatlens-scan-attempts-failing

**Means:** 3 or more scan attempts failed in 15 minutes. Each failed attempt is retried, so users may only see slower scans, but something outside is wrong.

**First look**, on `/aws/lambda/threatlens-worker`:

```
fields @timestamp, scan_id, attempt, error
| filter message = "scan attempt failed"
| stats count() by error
```

**Usually:**
- **Network or timeout errors:** OSV, EPSS, the KEV feed or GitHub is down or rate-limiting. Check their status pages. Partial answers already make a scan "partial" rather than failed (decisions 8, 11 and 12), so this is the all-out case. Nothing to do but wait.
- **`ClientError` from S3 or DynamoDB:** permissions or a missing resource, often right after a Terraform change. Compare the worker's role policy with the README's access table.
- **One `scan_id` again and again:** that file breaks the worker. It will end up failed after 3 attempts. Reproduce it locally.

A scan that ends `failed` is logged as `scan failed` and is not alarmed, because a bad file or a missing repository is the user's problem, not ours.

## Budget emails

These come from AWS Budgets, not CloudWatch, at 50% and 100% of actual spend and at 100% of the forecast (decision 55).

1. Open Cost Explorer, grouped by service, for this month.
2. Compare with the estimate in [WELL-ARCHITECTED.md](WELL-ARCHITECTED.md#cost-optimization). The usual suspects are X-Ray traces, API Gateway requests (look for a script hammering the API in the access logs) and DynamoDB writes (decision 39 caps them per user).
3. If one user is the cause, disable their account (`aws cognito-idp admin-disable-user`), then look at their requests by `user` in the API log.
