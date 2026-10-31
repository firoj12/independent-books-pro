# Independent Books Pro: Upgrade Status

This repository mirrors the readable source code, Android project, tests, launchers, and documentation from the original Independent Books project, with an additional cloud authentication/sync prototype in `cloud/`.

## What is included

- Original Independent Books application source and tests.
- Android Studio project and desktop launch scripts.
- `cloud/sync_service.py`: early multi-user authentication and sync-operation gateway.
- `cloud/API.md`: prototype API examples.
- Roles in the prototype: `admin`, `accountant`, and `viewer`.
- Password hashing with scrypt, expiring HMAC-signed tokens, a one-time admin bootstrap, audit events, and duplicate-operation retry handling.

## Important: sync is not production-ready

The cloud service is currently a separate prototype. It is **not yet connected to the accounting UI or the application's local accounting database**. It records JSON operations, but no client-side durable offline outbox or safe remote-operation applier has been integrated.

Before using this with real company books, the following work is still required:

1. Enforce company/tenant membership for every user and every sync request.
2. Integrate login and sync into the existing application UI and local database.
3. Add a durable offline operation queue, schema validation, replay, and version-based conflict handling.
4. Add automated integration tests for concurrent edits, duplicate retries, disconnects, and recovery.
5. Deploy behind HTTPS with managed secrets, persistent encrypted storage, backups, rate limiting, monitoring, and restore testing.

Do not expose the prototype HTTP server directly to the internet or store real accounting data in it yet. It binds to `127.0.0.1` by default.

## Run the local prototype

Python 3.10+ is recommended. The prototype uses only the Python standard library.

PowerShell example:

```powershell
$env:IB_TOKEN_SECRET = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
$env:IB_BOOTSTRAP_KEY = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
python cloud/sync_service.py
```

The first admin is created through `POST /api/bootstrap`; see `cloud/API.md` for request examples. Keep both secrets private and remove the bootstrap secret after setup.

## Files intentionally not copied

- Image/icon binaries such as `logo.png`, `app.icns`, and `*.ico` were not included in this GitHub transfer because the connected GitHub file reader only returned UTF-8 text files. The application source and text resources were copied.
- The upstream `books.json` file is actually a SQLite database, despite its extension. It was deliberately left out to avoid publishing local accounting data. It is ignored by `.gitignore`.

The original upstream project is at https://github.com/zoro-roronoa74/independent-books.
