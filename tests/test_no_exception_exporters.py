"""Nothing in the production environment exports exceptions outside `logging`.

The record factory (`postern_core.log_safety`) sanitises what goes through
`logging`. An OpenTelemetry SDK or exporter, or a Sentry-style SDK, records the
exception OBJECT (`span.record_exception(e)`, `set_status(str(e))`, an event
payload) and never touches a log record: a driver error's statement, bound
parameters and DETAIL would reach a third party with nothing in between. FastMCP
calls both on the span of every tool call.

Today none of it is there, and this file is what keeps it that way: it fails the
day one is added, and the failure is the prompt to write a scrubber first.

* the lock file, which is what the images install, names no such package;
* none is importable in this environment (`find_spec`);
* neither the Dockerfile nor `docker-compose.yml` sets an `OTEL_` or `SENTRY_`
  variable, a DSN or an exporter endpoint;
* FastMCP's tracer provider is OpenTelemetry's default proxy, which records
  nothing (checked in a fresh interpreter with no `OTEL_` variable).

`OTEL_SDK_DISABLED=true` was considered for the Dockerfile and not added: it
disables the SDK, which is not installed, so it would change nothing, and the
first assertion below would then have to carve an exception out of the rule it
exists to hold.
"""

import importlib.util
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent

#: Import names of SDKs and exporters that capture exception objects.
FORBIDDEN_MODULES = (
    "opentelemetry.sdk",
    "opentelemetry.exporter",
    "sentry_sdk",
    "ddtrace",
    "elasticapm",
)

#: Distribution names of the same, as `uv.lock` spells them.
FORBIDDEN_DISTRIBUTIONS = re.compile(
    r"^(opentelemetry-sdk|opentelemetry-exporter[a-z0-9-]*|opentelemetry-instrumentation[a-z0-9-]*"
    r"|opentelemetry-distro|sentry-sdk|ddtrace|elastic-apm|newrelic|honeycomb[a-z0-9-]*"
    r"|rollbar|bugsnag|raven)$"
)

FORBIDDEN_ENV = re.compile(
    r"\b(OTEL_[A-Z0-9_]+|SENTRY_[A-Z0-9_]+|DD_TRACE[A-Z0-9_]*|ELASTIC_APM[A-Z0-9_]*)"
)


def _find_spec(name: str) -> object | None:
    try:
        return importlib.util.find_spec(name)
    except ModuleNotFoundError:  # the parent package is absent too
        return None


@pytest.mark.parametrize("module", FORBIDDEN_MODULES)
def test_no_exporting_sdk_is_importable(module: str) -> None:
    assert _find_spec(module) is None, f"{module} is installed: write a scrubber first"


def test_the_lock_file_names_no_exporting_distribution() -> None:
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    names = sorted(package["name"] for package in lock["package"])
    assert names, "uv.lock lists no packages"
    assert "opentelemetry-api" in names  # the one the lock does carry, FastMCP's dependency
    assert [name for name in names if FORBIDDEN_DISTRIBUTIONS.match(name)] == []


def test_the_dockerfile_and_compose_set_no_exporter_variable() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    uncommented = "\n".join(
        line for line in dockerfile.splitlines() if not line.lstrip().startswith("#")
    )
    assert FORBIDDEN_ENV.findall(uncommented) == []

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    assert compose["services"], "compose declares no services"
    rendered = yaml.safe_dump(compose)
    assert FORBIDDEN_ENV.findall(rendered) == []


def test_the_scan_of_the_variables_would_see_one() -> None:
    assert FORBIDDEN_ENV.findall("ENV OTEL_EXPORTER_OTLP_ENDPOINT=http://x") == [
        "OTEL_EXPORTER_OTLP_ENDPOINT"
    ]
    assert FORBIDDEN_ENV.findall("SENTRY_DSN: https://k@o.ingest.sentry.io/1") == ["SENTRY_DSN"]
    assert FORBIDDEN_DISTRIBUTIONS.match("opentelemetry-sdk")
    assert FORBIDDEN_DISTRIBUTIONS.match("sentry-sdk")
    assert not FORBIDDEN_DISTRIBUTIONS.match("opentelemetry-api")


def test_fastmcps_tracer_provider_is_the_default_that_records_nothing() -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OTEL_", "SENTRY_"))}
    result = subprocess.run(  # noqa: S603 - fixed argv, this repo's own interpreter
        [
            sys.executable,
            "-c",
            "import fastmcp  # noqa: F401\n"
            "from opentelemetry import trace\n"
            "provider = trace.get_tracer_provider()\n"
            "print(type(provider).__module__, type(provider).__name__)\n"
            "span = trace.get_tracer('probe').start_span('probe')\n"
            "print(type(span).__name__, span.is_recording())\n",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    first, second = result.stdout.strip().splitlines()
    assert first == "opentelemetry.trace ProxyTracerProvider", first
    assert second == "NonRecordingSpan False", second
