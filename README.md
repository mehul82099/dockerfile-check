# dockerfile-check

A CI linter for Dockerfiles. It parses one or more Dockerfiles and reports
documented best-practice violations: mutable base-image tags, images that
run as root, `ADD` used where `COPY` suffices, `apt-get update` without an
install in the same `RUN`, secrets baked into `ENV`/`ARG`, and downloaded
scripts piped straight into a shell.

Pure Python standard library. No Docker, no daemon, no network - it reads
text, so it runs in any CI job.

## The problem

Dockerfiles get reviewed once and copy-pasted forever. The failure modes
are quiet: a `FROM python` build silently moves to a new major version
months later, an image runs as root because nobody added `USER`, a token
in an `ENV` ships inside every layer of a pushed image. Docker documents
each of these; the gap is that nothing checks them on every build.
dockerfile-check is that check, small enough to audit by reading the
source.

## Usage

```bash
python3 dockerfile_check.py Dockerfile
python3 dockerfile_check.py Dockerfile api/Dockerfile worker/Dockerfile
python3 dockerfile_check.py --fail-on-warning --format json Dockerfile
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean (warnings only when `--fail-on-warning` is off) |
| 1 | Findings present (errors, or warnings with `--fail-on-warning`) |
| 2 | Input problem: an unreadable file |

Example output:

```
Dockerfile:1 [warning] unpinned-base: FROM python resolves to the mutable "latest" tag; pin a version (image tags are mutable).
Dockerfile:4 [error] secret-in-env: ENV DB_PASSWORD is assigned a literal value; each ENV creates an image layer where the value persists even if later unset.
dockerfile-check: 1 error(s), 1 warning(s)
```

## Rules

| Rule | Severity | Trigger | Grounding |
|---|---|---|---|
| `unpinned-base` | warning | `FROM` image with no tag or `:latest` (digests pass; `scratch`, stage references, and `ARG` images are skipped) | Best practices: "Pin base image versions" - tags are mutable |
| `missing-user` | warning | Final build stage has no `USER`, or `USER` is `root`/`0`; a user inherited from a base stage counts | Best practices: "If a service can run without privileges, use `USER` to change to a non-root user" |
| `add-instead-of-copy` | warning | `ADD` whose sources are all local non-archive paths | Best practices: `COPY` covers basic copying; `ADD`'s extras are remote URL/Git fetching and automatic tar extraction |
| `apt-update-alone` | warning | `RUN` with `apt-get update` (or `apt update`) and no install in the same `RUN` | Best practices: "Always combine `RUN apt-get update` with `apt-get install` in the same `RUN`" |
| `secret-in-env` | error | `ENV`/`ARG` with a name like PASSWORD/SECRET/TOKEN/API_KEY assigned a literal value (`$VAR` references pass) | Best practices: each `ENV` creates a layer where the value persists even if later unset |
| `pipe-to-shell` | warning | `RUN` piping `curl`/`wget` output into `sh`/`bash` | Heuristic (not from Docker docs): executes unaudited remote code |
| `healthcheck-missing` | warning | No `HEALTHCHECK` instruction; only with `--require-healthcheck` | Optional hygiene check |

## Options

```
--ignore RULE            suppress a rule by name (repeatable)
--require-healthcheck    warn when no HEALTHCHECK instruction is present
--fail-on-warning        exit 1 when only warnings are present
--format text|json       output format (default: text)
```

## Caveats

- This is a static text lint, not a build: it cannot resolve `ARG`-based
  `FROM` images (skipped, not flagged) and does not evaluate shell.
- `pipe-to-shell` is a heuristic and says so; the other rules cite the
  Docker documentation they implement.
- `missing-user` cannot know whether your service genuinely needs root;
  suppress it with `--ignore missing-user` where it does.

## Sources

- Dockerfile reference: https://docs.docker.com/reference/dockerfile/
- Build best practices: https://docs.docker.com/build/building/best-practices/

## Development

71 tests, all fabricated Dockerfiles, no Docker required:

```bash
python3 -m unittest -v
```

CI runs the suite on Ubuntu and Windows with Python 3.9 and 3.13.

## License

MIT - see LICENSE.
