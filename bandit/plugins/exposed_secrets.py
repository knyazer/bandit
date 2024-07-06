import re
import functools
import tomllib
from pathlib import Path

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

_UNMATCHABLE_REGEX = re.compile(r"\b\B")


def _regex_wrap(regex: str) -> str:
    # first step: add boundary tokens
    regex = r"\b" + regex + r"\b"
    # TODO: ignore 'xxxxxx' and 'EXAMPLE' with lookahead
    return regex


class _Secret:
    # Specifies a particular secret, without storing the actual secret string
    name: str  # short name, e.g. AWS Cloud
    regex: str  # this is a partial (raw) regex, meaning no boundary tokens
    false_positive_rate: float  # 1 -> very bad, 0 -> very good

    def __init__(self, name: str, regex: str | None = None, false_positive_rate: float = 1.0):
        self.name = name
        if regex is not None:
            self.regex = re.compile(_regex_wrap(regex))
        else:
            self.regex = _UNMATCHABLE_REGEX
        self.false_positive_rate = false_positive_rate


_GENERIC_SECRET = _Secret("generic")


def _make_issue(secret_spec: _Secret):
    confidence = bandit.LOW
    if secret_spec.false_positive_rate < 0.1:
        confidence = bandit.MEDIUM
    if secret_spec.false_positive_rate < 0.01:
        confidence = bandit.HIGH
    return bandit.Issue(
        severity=bandit.HIGH,  # any leaked keys are critically bad
        confidence=confidence,
        cwe=issue.Cwe.NOTSET,
        text=f"{secret_spec.name} secret is stored in a string.",
    )


@functools.cache
def _get_database(filename: str = "secrets.toml") -> list[_Secret]:
    # Loads the file with regexes; uses cache
    with Path(__file__).with_name(filename).open("rb") as f:
        contents = tomllib.load(f)
    # contents is {'name': {'regex': ..., 'false_positive_rate': ..., ...}, ...}
    db = [_Secret(name=key, **val) for key, val in contents.items()]
    # remove all the secrets that are unmatchable
    db = [secret for secret in db if secret.regex != _UNMATCHABLE_REGEX]
    return db


def _detect_secrets(string_to_check: str) -> list[_Secret]:
    db = _get_database()
    return [secret for secret in db if re.search(secret.regex, string_to_check) is not None]


@test.checks("Str")
@test.test_id("B510")
def exposed_secrets(context):
    detected_secrets = _detect_secrets(context.string_val)
    if len(detected_secrets) == 0:
        return None
    elif len(detected_secrets) == 1:
        return _make_issue(detected_secrets[0])
    else:
        return _make_issue(_GENERIC_SECRET)
