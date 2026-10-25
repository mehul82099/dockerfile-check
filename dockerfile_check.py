#!/usr/bin/env python3
"""dockerfile-check - a CI linter for Dockerfiles.

Parses one or more Dockerfiles and reports findings for a short list of
documented best-practice rules: unpinned base images, missing non-root
USER, ADD used where COPY suffices, `apt-get update` without install in
the same RUN, secrets baked into ENV/ARG, and remote scripts piped to a
shell. Pure standard library; no Docker required.

Rule grounding:
- Dockerfile reference: https://docs.docker.com/reference/dockerfile/
- Build best practices: https://docs.docker.com/build/building/best-practices/
"""

import argparse
import json
import re
import sys

SECRET_NAME = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)",
    re.IGNORECASE)
APT_UPDATE = re.compile(r"\bapt(?:-get)?\s+update\b")
APT_INSTALL = re.compile(r"\bapt(?:-get)?\s+install\b")
PIPE_TO_SHELL = re.compile(
    r"\b(curl|wget)\b[^|&;]*\|\s*(?:sudo\s+)?(?:ba|da|z)?sh\b")
TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
                ".tar.xz", ".txz")
URL_PREFIXES = ("http://", "https://", "git@", "ssh://")
ROOT_USERS = {"root", "0", "0:0", "root:root"}


class Finding:
    def __init__(self, path, line, rule, severity, message):
        self.path = path
        self.line = line
        self.rule = rule
        self.severity = severity  # "error" or "warning"
        self.message = message

    def as_dict(self):
        return {
            "file": self.path,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }


def logical_lines(text):
    """Yield (start_lineno, logical_instruction_text) with continuations
    joined and full-line comments / parser directives dropped. Dockerfiles
    only treat # as a comment at the start of a line."""
    out = []
    buf = None
    start = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if buf is None:
            if not stripped or stripped.startswith("#"):
                continue
            start = lineno
            buf = raw.rstrip()
        else:
            buf += raw.rstrip()
        if buf.endswith("\\"):
            buf = buf[:-1]
            continue
        out.append((start, buf.strip()))
        buf = None
        start = None
    if buf is not None:
        out.append((start, buf.strip()))
    return out


def parse_instructions(text):
    """Yield (lineno, instruction, args). Instruction is uppercased."""
    for lineno, line in logical_lines(text):
        parts = line.split(None, 1)
        if not parts:
            continue
        yield lineno, parts[0].upper(), (parts[1] if len(parts) > 1 else "")


def parse_from(args):
    """Parse FROM args -> (image, stage_name_or_None). Returns None when
    unparseable or the image is an ARG reference."""
    tokens = args.split()
    tokens = [t for t in tokens if not t.startswith("--")]
    if not tokens:
        return None
    image = tokens[0]
    stage = None
    if len(tokens) >= 3 and tokens[1].upper() == "AS":
        stage = tokens[2].lower()
    if image.startswith("$"):
        return None  # ARG-based image; tag cannot be resolved statically
    return image, stage


def image_uses_latest(image):
    """True when the image reference resolves to the mutable latest tag.
    Digest-pinned references and explicit non-latest tags pass."""
    if "@" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return True
    return last.rsplit(":", 1)[1] == "latest"


def parse_env_pairs(args):
    """Parse ENV args into (name, value) pairs. Supports KEY=VAL lists and
    the legacy `KEY VALUE` form."""
    pairs = []
    tokens = args.split()
    if tokens and "=" not in tokens[0] and len(tokens) >= 2:
        # legacy: ENV NAME value words...
        return [(tokens[0], " ".join(tokens[1:]))]
    for tok in tokens:
        if "=" in tok:
            name, value = tok.split("=", 1)
            pairs.append((name, value.strip("\"'")))
    return pairs


def parse_arg(args):
    """Parse ARG args -> (name, default_or_None) for the first declared
    variable (ARG declares one variable per instruction)."""
    tok = args.split()[0] if args.split() else ""
    if "=" in tok:
        name, value = tok.split("=", 1)
        return name, value.strip("\"'")
    return tok, None


def _is_reference_value(value):
    return value.startswith("$") or value == ""


def check_dockerfile(text, path, require_healthcheck=False):
    findings = []

    def emit(line, rule, severity, message):
        findings.append(Finding(path, line, rule, severity, message))

    stages = []  # {name, user, base}
    current = None
    seen_healthcheck = False

    for lineno, instr, args in parse_instructions(text):
        if instr == "FROM":
            parsed = parse_from(args)
            base = parsed[0] if parsed else None
            name = parsed[1] if parsed else None
            current = {"name": name, "user": None,
                       "base": base, "line": lineno}
            stages.append(current)
            if base and base.lower() != "scratch" and \
                    base.lower() not in {s["name"] for s in stages[:-1]
                                         if s["name"]}:
                if image_uses_latest(base):
                    emit(lineno, "unpinned-base", "warning",
                         "FROM %s resolves to the mutable \"latest\" tag; "
                         "pin a version (image tags are mutable)." % base)
        elif instr == "USER":
            user = args.split()[0].lower() if args.split() else ""
            if current is not None:
                current["user"] = user
        elif instr == "ADD":
            sources = [t for t in args.split() if not t.startswith("--")][:-1]
            if sources and all(
                    not s.startswith(URL_PREFIXES)
                    and not s.lower().endswith(TAR_SUFFIXES)
                    and not s.startswith("$")
                    for s in sources):
                emit(lineno, "add-instead-of-copy", "warning",
                     "ADD with only local non-archive sources does nothing "
                     "COPY cannot; use COPY (ADD's extras are remote URL/Git "
                     "fetch and automatic tar extraction).")
        elif instr == "RUN":
            if APT_UPDATE.search(args) and not APT_INSTALL.search(args):
                emit(lineno, "apt-update-alone", "warning",
                     "RUN apt-get update without apt-get install in the same "
                     "RUN causes caching issues; combine them in one RUN.")
            if PIPE_TO_SHELL.search(args):
                emit(lineno, "pipe-to-shell", "warning",
                     "piping a downloaded script straight into a shell "
                     "executes unaudited remote code (heuristic rule).")
        elif instr == "ENV":
            for name, value in parse_env_pairs(args):
                if SECRET_NAME.search(name) and not _is_reference_value(value):
                    emit(lineno, "secret-in-env", "error",
                         "ENV %s is assigned a literal value; each ENV "
                         "creates an image layer where the value persists "
                         "even if later unset." % name)
        elif instr == "ARG":
            name, value = parse_arg(args)
            if value is not None and SECRET_NAME.search(name) and \
                    not _is_reference_value(value):
                emit(lineno, "secret-in-env", "error",
                     "ARG %s has a literal secret-looking default; build "
                     "args are visible in image build history." % name)
        elif instr == "HEALTHCHECK":
            seen_healthcheck = True

    # missing non-root user: check the final stage's effective user,
    # walking base-stage chains (stage names are case-insensitive).
    if stages:
        by_name = {s["name"]: s for s in stages if s["name"]}
        effective = None
        seen = set()
        stage = stages[-1]
        while stage is not None and id(stage) not in seen:
            seen.add(id(stage))
            if stage["user"] is not None:
                effective = stage["user"]
                break
            stage = by_name.get((stage["base"] or "").lower())
        if effective is None:
            emit(stages[-1]["line"], "missing-user", "warning",
                 "no USER instruction; the image runs as root by default "
                 "(docs: if a service can run without privileges, use USER "
                 "to switch to a non-root user).")
        elif effective in ROOT_USERS:
            emit(stages[-1]["line"], "missing-user", "warning",
                 "USER is %s; the container still runs as root." % effective)

    if require_healthcheck and not seen_healthcheck:
        emit(1, "healthcheck-missing", "warning",
             "no HEALTHCHECK instruction (--require-healthcheck).")

    return findings


def format_text(results):
    lines = []
    errors = warnings = 0
    for path, findings in results:
        for f in findings:
            lines.append("%s:%d [%s] %s: %s" % (
                f.path, f.line, f.severity, f.rule, f.message))
            if f.severity == "error":
                errors += 1
            else:
                warnings += 1
    if errors or warnings:
        lines.append("dockerfile-check: %d error(s), %d warning(s)" % (
            errors, warnings))
    else:
        lines.append("dockerfile-check: clean")
    return "\n".join(lines), errors, warnings


def format_json(results, errors, warnings):
    return json.dumps({
        "findings": [f.as_dict() for _, fs in results for f in fs],
        "summary": {"files": len(results), "errors": errors,
                    "warnings": warnings},
    }, indent=2)


def build_parser():
    p = argparse.ArgumentParser(
        prog="dockerfile-check",
        description="Lint Dockerfiles for documented best-practice "
                    "violations. No Docker required.")
    p.add_argument("dockerfiles", nargs="+",
                   help="path(s) to Dockerfile(s)")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="suppress a rule by name (repeatable)")
    p.add_argument("--require-healthcheck", action="store_true",
                   help="warn when no HEALTHCHECK instruction is present")
    p.add_argument("--fail-on-warning", action="store_true",
                   help="exit 1 when only warnings are present")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    ignore = set(args.ignore)
    results = []
    for path in args.dockerfiles:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            print("dockerfile-check: cannot read %s: %s" % (path, exc),
                  file=sys.stderr)
            return 2
        findings = check_dockerfile(
            text, path, require_healthcheck=args.require_healthcheck)
        findings = [f for f in findings if f.rule not in ignore]
        results.append((path, findings))

    text_out, errors, warnings = format_text(results)
    if args.format == "json":
        print(format_json(results, errors, warnings))
    else:
        print(text_out)
    if errors:
        return 1
    if args.fail_on_warning and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
