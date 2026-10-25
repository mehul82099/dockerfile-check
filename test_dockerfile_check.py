import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dockerfile_check as dc


def lint(text, require_healthcheck=False):
    return dc.check_dockerfile(text, "Dockerfile",
                               require_healthcheck=require_healthcheck)


def rules(findings):
    return [f.rule for f in findings]


class LogicalLinesTests(unittest.TestCase):
    def test_continuation_joined(self):
        lines = dc.logical_lines("RUN apt-get update && \\\n    apt-get install -y curl")
        self.assertEqual(lines, [(1, "RUN apt-get update &&     apt-get install -y curl")])

    def test_full_line_comments_dropped(self):
        self.assertEqual(dc.logical_lines("# comment\nFROM x"), [(2, "FROM x")])

    def test_parser_directive_dropped(self):
        lines = dc.logical_lines("# syntax=docker/dockerfile:1\nFROM x")
        self.assertEqual(lines, [(2, "FROM x")])

    def test_inline_hash_is_not_a_comment(self):
        lines = dc.logical_lines("RUN echo a#b")
        self.assertEqual(lines, [(1, "RUN echo a#b")])

    def test_blank_lines_dropped(self):
        self.assertEqual(dc.logical_lines("FROM x\n\n\nRUN y"),
                         [(1, "FROM x"), (4, "RUN y")])

    def test_trailing_continuation_at_eof(self):
        lines = dc.logical_lines("RUN a \\")
        self.assertEqual(lines, [(1, "RUN a")])

    def test_line_numbers_track_first_physical_line(self):
        lines = dc.logical_lines("FROM x\nRUN a && \\\n    b\nRUN c")
        self.assertEqual([l for l, _ in lines], [1, 2, 4])


class ParseFromTests(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(dc.parse_from("python:3.12"), ("python:3.12", None))

    def test_with_stage(self):
        self.assertEqual(dc.parse_from("golang:1.22 AS build"),
                         ("golang:1.22", "build"))

    def test_stage_case_insensitive(self):
        self.assertEqual(dc.parse_from("golang AS Build")[1], "build")

    def test_platform_flag_stripped(self):
        self.assertEqual(dc.parse_from("--platform=linux/arm64 alpine:3.21"),
                         ("alpine:3.21", None))

    def test_arg_image_unparseable(self):
        self.assertIsNone(dc.parse_from("${BASE_IMAGE}"))

    def test_empty(self):
        self.assertIsNone(dc.parse_from(""))


class LatestTagTests(unittest.TestCase):
    def test_no_tag_is_latest(self):
        self.assertTrue(dc.image_uses_latest("python"))

    def test_explicit_latest(self):
        self.assertTrue(dc.image_uses_latest("python:latest"))

    def test_pinned_tag_passes(self):
        self.assertFalse(dc.image_uses_latest("python:3.12"))

    def test_digest_passes(self):
        self.assertFalse(dc.image_uses_latest("python@sha256:abc"))

    def test_registry_port_not_a_tag(self):
        self.assertTrue(dc.image_uses_latest("registry:5000/team/app"))

    def test_registry_port_with_tag(self):
        self.assertFalse(dc.image_uses_latest("registry:5000/team/app:1.2"))

    def test_scratch_skipped_at_rule_level(self):
        self.assertEqual(rules(lint("FROM scratch\nUSER 1000")), [])


class EnvParsingTests(unittest.TestCase):
    def test_key_value_pairs(self):
        self.assertEqual(dc.parse_env_pairs("A=1 B=2"), [("A", "1"), ("B", "2")])

    def test_legacy_form(self):
        self.assertEqual(dc.parse_env_pairs("A hello world"), [("A", "hello world")])

    def test_quotes_stripped(self):
        self.assertEqual(dc.parse_env_pairs('A="x"'), [("A", "x")])

    def test_arg_with_default(self):
        self.assertEqual(dc.parse_arg("TOKEN=abc"), ("TOKEN", "abc"))

    def test_arg_without_default(self):
        self.assertEqual(dc.parse_arg("TOKEN"), ("TOKEN", None))


class RuleTests(unittest.TestCase):
    def test_unpinned_base(self):
        f = lint("FROM python\nUSER 1000")
        self.assertIn("unpinned-base", rules(f))

    def test_pinned_base_clean(self):
        f = lint("FROM python:3.12\nUSER 1000")
        self.assertEqual(f, [])

    def test_digest_base_clean(self):
        f = lint("FROM python@sha256:abc123\nUSER 1000")
        self.assertEqual(f, [])

    def test_stage_reference_not_flagged(self):
        text = ("FROM golang:1.22 AS build\n"
                "FROM build\nUSER 1000")
        self.assertEqual(rules(lint(text)), [])

    def test_stage_reference_case_insensitive(self):
        text = ("FROM golang:1.22 AS Build\n"
                "FROM build\nUSER 1000")
        self.assertEqual(rules(lint(text)), [])

    def test_missing_user(self):
        f = lint("FROM python:3.12")
        self.assertIn("missing-user", rules(f))
        self.assertEqual(f[0].severity, "warning")

    def test_user_root_flagged(self):
        f = lint("FROM python:3.12\nUSER root")
        self.assertIn("missing-user", rules(f))

    def test_user_uid_zero_flagged(self):
        f = lint("FROM python:3.12\nUSER 0")
        self.assertIn("missing-user", rules(f))

    def test_user_name_passes(self):
        self.assertEqual(rules(lint("FROM python:3.12\nUSER app")), [])

    def test_user_uid_passes(self):
        self.assertEqual(rules(lint("FROM python:3.12\nUSER 1000")), [])

    def test_user_inherited_from_base_stage(self):
        text = ("FROM python:3.12 AS base\nUSER app\n"
                "FROM base\nRUN true")
        self.assertNotIn("missing-user", rules(lint(text)))

    def test_user_override_in_final_stage(self):
        text = ("FROM python:3.12 AS base\nUSER app\n"
                "FROM base\nUSER root")
        self.assertIn("missing-user", rules(lint(text)))

    def test_add_local_flagged(self):
        f = lint("FROM python:3.12\nUSER app\nADD app.py /srv/")
        self.assertIn("add-instead-of-copy", rules(f))

    def test_add_multiple_local_flagged(self):
        f = lint("FROM python:3.12\nUSER app\nADD a.txt b.txt /srv/")
        self.assertIn("add-instead-of-copy", rules(f))

    def test_copy_clean(self):
        self.assertEqual(rules(lint("FROM python:3.12\nUSER app\nCOPY app.py /srv/")), [])

    def test_add_url_allowed(self):
        f = lint("FROM python:3.12\nUSER app\nADD https://example.com/f.bin /srv/")
        self.assertNotIn("add-instead-of-copy", rules(f))

    def test_add_tarball_allowed(self):
        f = lint("FROM python:3.12\nUSER app\nADD bundle.tar.gz /srv/")
        self.assertNotIn("add-instead-of-copy", rules(f))

    def test_apt_update_alone(self):
        f = lint("FROM ubuntu:24.04\nUSER app\nRUN apt-get update")
        self.assertIn("apt-update-alone", rules(f))

    def test_apt_update_with_install_clean(self):
        text = ("FROM ubuntu:24.04\nUSER app\n"
                "RUN apt-get update && apt-get install -y curl")
        self.assertNotIn("apt-update-alone", rules(lint(text)))

    def test_apt_without_get(self):
        f = lint("FROM ubuntu:24.04\nUSER app\nRUN apt update")
        self.assertIn("apt-update-alone", rules(f))

    def test_curl_pipe_sh(self):
        f = lint("FROM alpine:3.21\nUSER app\nRUN curl https://x.sh | sh")
        self.assertIn("pipe-to-shell", rules(f))

    def test_wget_pipe_bash(self):
        f = lint("FROM alpine:3.21\nUSER app\nRUN wget -qO- https://x.sh | bash")
        self.assertIn("pipe-to-shell", rules(f))

    def test_curl_without_pipe_clean(self):
        text = ("FROM alpine:3.21\nUSER app\n"
                "RUN curl -o /tmp/x.sh https://x.sh && sh /tmp/x.sh")
        self.assertNotIn("pipe-to-shell", rules(lint(text)))

    def test_secret_in_env(self):
        f = lint("FROM python:3.12\nUSER app\nENV DB_PASSWORD=hunter2")
        self.assertEqual(f[0].rule, "secret-in-env")
        self.assertEqual(f[0].severity, "error")

    def test_secret_in_arg(self):
        f = lint("FROM python:3.12\nUSER app\nARG API_KEY=abc123")
        self.assertEqual(f[0].rule, "secret-in-env")
        self.assertEqual(f[0].severity, "error")

    def test_arg_without_default_clean(self):
        self.assertEqual(rules(lint("FROM python:3.12\nUSER app\nARG API_KEY")), [])

    def test_env_reference_value_clean(self):
        self.assertEqual(rules(lint("FROM python:3.12\nUSER app\nENV TOKEN=$OTHER")), [])

    def test_env_empty_value_clean(self):
        self.assertEqual(rules(lint("FROM python:3.12\nUSER app\nENV PASSWORD=")), [])

    def test_non_secret_env_clean(self):
        self.assertEqual(rules(lint("FROM python:3.12\nUSER app\nENV APP_ENV=prod")), [])

    def test_legacy_env_secret(self):
        f = lint("FROM python:3.12\nUSER app\nENV AWS_SECRET_ACCESS_KEY xyz")
        self.assertEqual(f[0].rule, "secret-in-env")

    def test_case_insensitive_instructions(self):
        f = lint("from python\nuser app")
        self.assertIn("unpinned-base", rules(f))
        self.assertNotIn("missing-user", rules(f))

    def test_healthcheck_required(self):
        f = lint("FROM python:3.12\nUSER app", require_healthcheck=True)
        self.assertIn("healthcheck-missing", rules(f))

    def test_healthcheck_present(self):
        text = ("FROM python:3.12\nUSER app\n"
                "HEALTHCHECK CMD curl -f http://localhost/ || exit 1")
        f = lint(text, require_healthcheck=True)
        self.assertNotIn("healthcheck-missing", rules(f))

    def test_healthcheck_not_required_by_default(self):
        self.assertEqual(rules(lint("FROM python:3.12\nUSER app")), [])

    def test_finding_has_line_and_path(self):
        f = lint("FROM python\n\nRUN apt-get update\nUSER app")
        by_rule = {x.rule: x for x in f}
        self.assertEqual(by_rule["unpinned-base"].line, 1)
        self.assertEqual(by_rule["apt-update-alone"].line, 3)
        self.assertEqual(by_rule["unpinned-base"].path, "Dockerfile")

    def test_clean_realistic_multistage(self):
        text = (
            "# syntax=docker/dockerfile:1\n"
            "FROM golang:1.22 AS build\n"
            "WORKDIR /src\n"
            "COPY . .\n"
            "RUN CGO_ENABLED=0 go build -o /out/app ./cmd/app\n"
            "\n"
            "FROM gcr.io/distroless/static:nonroot\n"
            "COPY --from=build /out/app /app\n"
            "USER nonroot\n"
            "ENTRYPOINT [\"/app\"]\n")
        self.assertEqual(rules(lint(text)), [])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = dc.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_0(self):
        path = self.write("Dockerfile", "FROM python:3.12\nUSER app\n")
        code, out, _ = self.run_cli([path])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_warning_only_exit_0(self):
        path = self.write("Dockerfile", "FROM python\nUSER app\n")
        code, _, _ = self.run_cli([path])
        self.assertEqual(code, 0)

    def test_fail_on_warning_exit_1(self):
        path = self.write("Dockerfile", "FROM python\nUSER app\n")
        code, _, _ = self.run_cli([path, "--fail-on-warning"])
        self.assertEqual(code, 1)

    def test_error_exit_1(self):
        path = self.write("Dockerfile", "FROM python:3.12\nUSER app\nENV PASSWORD=x\n")
        code, out, _ = self.run_cli([path])
        self.assertEqual(code, 1)
        self.assertIn("1 error(s)", out)

    def test_missing_file_exit_2(self):
        code, _, err = self.run_cli([os.path.join(self.dir, "Nope")])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_multiple_files(self):
        a = self.write("Dockerfile.a", "FROM python\nUSER app\n")
        b = self.write("Dockerfile.b", "FROM python:3.12\nUSER app\n")
        code, out, _ = self.run_cli([a, b])
        self.assertEqual(code, 0)
        self.assertIn(a, out)
        self.assertNotIn(b + ":", out.replace(a, ""))

    def test_ignore_flag(self):
        path = self.write("Dockerfile", "FROM python\nUSER app\n")
        code, out, _ = self.run_cli([path, "--ignore", "unpinned-base"])
        self.assertEqual(code, 0)
        self.assertNotIn("unpinned-base", out)

    def test_json_output(self):
        path = self.write("Dockerfile", "FROM python\nUSER app\n")
        code, out, _ = self.run_cli([path, "--format", "json"])
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertEqual(parsed["summary"]["warnings"], 1)
        self.assertEqual(parsed["findings"][0]["rule"], "unpinned-base")
        self.assertEqual(parsed["findings"][0]["file"], path)

    def test_require_healthcheck_flag(self):
        path = self.write("Dockerfile", "FROM python:3.12\nUSER app\n")
        code, out, _ = self.run_cli([path, "--require-healthcheck"])
        self.assertEqual(code, 0)
        self.assertIn("healthcheck-missing", out)

    def test_output_contains_path_and_line(self):
        path = self.write("Dockerfile", "FROM python\nUSER app\n")
        _, out, _ = self.run_cli([path])
        self.assertIn("%s:1 [warning] unpinned-base" % path, out)


if __name__ == "__main__":
    unittest.main()
