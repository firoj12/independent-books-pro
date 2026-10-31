# Cloud Sync Prototype API

All endpoints use JSON. Protected endpoints require `Authorization: Bearer <access_token>`.
The service is a prototype. Use HTTPS at the reverse proxy for remote access.

## Health
`GET /health`

## Bootstrap the first admin
`POST /api/bootstrap`
```json
{"bootstrap_key":"<IB_BOOTSTRAP_KEY>","username":"admin","password":"a-long-unique-password"}
```
Only works while the user table is empty. Use a one-time secret and remove it from the environment after bootstrap.

## Login
`POST /api/login`
```json
{"username":"admin","password":"a-long-unique-password"}
```

## Current user
`GET /api/me`

## Create user (admin only)
`POST /api/users`
```json
{"username":"accounts1","password":"a-long-unique-password","role":"accountant"}
```
Valid roles: `admin`, `accountant`, `viewer`.

## Push operations (admin/accountant)
`POST /api/sync/push`
```json
{
  "company_id":"company-uuid",
  "operations":[
    {"op_id":"client-generated-unique-id","type":"voucher.create","payload":{"voucher_id":"voucher-uuid","data":{}}}
  ]
}
```
Each operation needs a stable unique `op_id`. Retrying a push with the same `op_id` will not insert the operation a second time.

## Pull operations (authenticated)
`GET /api/sync/pull?company_id=company-uuid&after=0`
Returns up to 500 operations after the numeric cursor. Persist the returned `next_cursor` on the client only after successfully applying the returned operations.

## Current limitations
- Company membership is not yet enforced. Do not use this prototype with real business data or expose it publicly.
- Pull returns the operation log, but the client must validate and apply each operation to the accounting database.
- Conflict detection/resolution and compaction are not implemented.
