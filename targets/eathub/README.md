# eathub — Express/SQLite web-app target

EatHub is a recipe-sharing JSON API (Express 4, `passport` local auth,
`express-session` over a SQLite store). It is the worked web-app target for the
vuln-pipeline and its fast smoke test. The app is vendored under `app/`; the
replay runner and fixture live beside it.

Unlike the C targets the pipeline shipped originally, the "detector" here is not
AddressSanitizer. It is `run_poc.js`: a runner that boots the app on loopback,
replays a JSON PoC against it, and evaluates a set of security **oracles**,
printing a `<<<DETECTION>>>` block and exiting `0` (nothing fired) / `1`
(runner/infra error) / `2` (an oracle fired) / `3` (hang).

## Quick start

```bash
# from repo root, inside the sandbox (see docs/security.md)
bin/vp-sandboxed run eathub --model claude-opus-5 --runs 3 --parallel --stream --max-turns 100
```

The flagship finding — a check-then-act race in the like/ranking counter —
lands first on most runs. Reports stream into
`results/eathub/<ts>/reports/bug_NN/`.

**Never pass `--novelty`.** `config.yaml`'s `github_url` is a prose placeholder
(this is a private, local app with no canonical upstream). The pipeline refuses
`--novelty` for such a target rather than handing that string to `git clone`.

## Layout (load-bearing)

```
/work/app             the application; source_root; a git repo with a baseline
/work/run_poc.js      the replay runner, ONE level above source_root
/work/seed.js         the deterministic fixture
/work/frontend/dist/  the SPA-shell stub the app expects at __dirname/../frontend/dist
/work/.replays/       per-replay scratch (created + swept by the runner)
```

The runner sits **above** `source_root` on purpose: a patch agent's `git diff`
is scoped to `/work/app`, so no diff it emits can modify its own verifier, and
the runner is outside `app/test/no_console.test.js`'s scanned tree (it prints a
detection block, which that test would otherwise flag as a stray `console`).

### The SPA-shell trap

`index.js` serves `app.get('*')` from `__dirname/../frontend/dist/index.html`,
which the real repo builds separately and this target does not ship. Without a
stub, a bare `GET /` throws `ENOENT` → `'unhandled error'` on a completely
healthy app, and the `UNCAUGHT_EXCEPTION` oracle would fire on a non-bug. Two
defences: the image ships a stub at `/work/frontend/dist/index.html` (which is
why the runner copies `frontend/` alongside `app/` per replay), and the runner
filters `'unhandled error'` lines whose `err.code === 'ENOENT'` and path is the
SPA shell. The negative-control fixture proves both hold.

## The oracle set

Evaluated after every replay, reported in this precedence (highest first):

| Class | Kind | Fires when |
|---|---|---|
| `DATA_INTEGRITY_VIOLATION` | always-on + declared | duplicate `(recipe,user)` like rows; `ranking` counter disagreeing with the like rows; a negative counter; or a declared invariant that fails |
| `CROSS_ACCOUNT_ACCESS` | always-on | a 2xx under one session reads/mutates another user's row (safety net — the ownership checks look correct) |
| `ORIGIN_ESCAPE` | PoC-triggered | a `Location` or verification link resolving off-origin — needs a hostile `Host` header |
| `CORS_POLICY_VIOLATION` | PoC-triggered | reflected `Origin` + `Access-Control-Allow-Credentials: true` — needs an `Origin` header |
| `UNSAFE_CONTENT_TYPE` | PoC-triggered | an upload served with an active type or a `Content-Type` disagreeing with its magic bytes — needs a mismatched upload |
| `INFO_DISCLOSURE` | always-on | a response body with a stack trace, SQLite driver error, or hash/token field |
| `UNCAUGHT_EXCEPTION` | always-on | an `'unhandled error'`/`'unhandled promise rejection'` log line (SPA-shell 404 excluded), or the app process exiting mid-replay |
| `UNEXPECTED_5XX` | always-on | any 5xx (SPA-shell 404 excluded, correlated by `reqId`) |
| `HANG` | always-on | a request or the whole replay exceeding its time budget |

Several classes routinely fire from one event; `primary_class` is the highest
that fired, and dedup / grading key on it. See `harness/detection.py`.

## Fixtures

- `fixtures/race_poc.json` — the flagship like/ranking race. `repeat: 5` is the
  measured floor: `2` fires 5/6, `3` often lands on a self-consistent end state
  and fires nothing, `5` fires 10/10, `10` fires 9/10, `20` crosses into an
  unresolved-promise hang (exit 3). Exits 2.
- `fixtures/example_poc.json` — the schema exhibit: hostile `Host`, an
  stdout-capture spanning a newline, a multipart upload, a captured server-side
  id, a race, and a declared invariant. Exits 2.
- `fixtures/benign_poc.json` — the negative control. Exercises the SPA shell, an
  anonymous read, a login, an authenticated read. Must exit 0 with nothing
  fired — proves the SPA stub survived the per-replay copy and the
  `UNEXPECTED_5XX` reqId correlation discriminates rather than just silencing.

## Coverage against the triaged findings

This target was scoped against a prior static triage of the app (`TRIAGE.json`
in the app's own repo). An execution-verified pipeline can only produce PoCs for
defects reachable from the HTTP surface, so the honest coverage is **3 of 7**
triaged true positives:

| Finding | Sev | v1 oracle coverage |
|---|---|---|
| Upload content-type confusion | HIGH | `UNSAFE_CONTENT_TYPE` (PoC-triggered) |
| Google account-takeover via email linking | HIGH | **not covered** — needs an OAuth stub |
| CORS reflects any origin with credentials | MED | `CORS_POLICY_VIOLATION` |
| Host-header verification links | MED | `ORIGIN_ESCAPE` |
| OAuth missing `state` | MED | **not covered** — needs an OAuth stub |
| `SESSION_SECRET` dev fallback | MED | out of scope — hardening, no reachable PoC (server-side store) |
| Unbounded email regex (ReDoS) | LOW | not covered — measured non-issue (0.26 ms at the 100 kB cap) |

The two uncovered HIGH/MED findings (account takeover, missing `state`) both
require a Google OAuth stub — a local fake IdP plus `GOOGLE_CLIENT_ID` wired
into the seed. That is deferred to a v2: it is new attack surface that can
itself produce false positives, and it slots in independently of everything
here. The flagship race is not in the triage list at all — it was found by
execution, which is the point.

Also confirmed out of scope (refuted by the static triage, and re-checked
before building): SQLi via `dbFind`/`dbDel` (no user-controlled call site),
`generateRecipeId` collisions (INTEGER PRIMARY KEY, not expressible), and the
`safeNext` open redirect (sink is dead — `req.login` drops `returnTo` first).
The find prompt names all of these so agents don't burn turns on them.

## Notes

- Login is by **email**, not username (`local_strategy.js` sets
  `usernameField: "email"`). The seed's `email_verified = 1` on alice/bob is
  load-bearing — `local_strategy.js` refuses to sign in an unverified account.
- The verification link is `console.log`, not pino (a deliberate dev fallback),
  so the `ORIGIN_ESCAPE` oracle scans plain-text stdout, and a `from: "stdout"`
  capture reads it.
- `express-sqlite3` never actually enables WAL (an upstream typo:
  `concurentDb` set vs. `concurrentDb` read), so the runner deletes
  `main.db-wal`/`-shm` defensively but they rarely exist.
