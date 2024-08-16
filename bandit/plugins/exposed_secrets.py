import re
import functools
import tomllib
from pathlib import Path

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

_UNMATCHABLE_REGEX = re.compile(r"\b\B")


@functools.cache
def _get_ignore_list(filename: str = "new_secrets.toml") -> list[re.Pattern]:
    with Path(__file__).with_name(filename).open("rb") as f:
        contents = tomllib.load(f)

    # Compile the reject rules into regex patterns
    return [re.compile(rule, re.IGNORECASE) for rule in contents.get("reject-rules", [])]


_IGNORE_LIST = _get_ignore_list()


class _Secret:
    # Specifies a particular secret, without storing the actual secret string
    id: str  # unique identifier for the secret
    description: str  # description of the secret
    regex: re.Pattern  # compiled regex pattern for the secret
    severity: str  # severity level

    def __init__(self, id: str, description: str, regex: str, severity: str):
        self.id = id
        self.description = description
        self.regex = re.compile(regex, re.IGNORECASE) if regex else _UNMATCHABLE_REGEX
        self.severity = severity


_GENERIC_SECRET = _Secret("generic", "Generic secret", regex="", severity="high")


def _make_issue(secret_spec: _Secret):
    severity = getattr(bandit, secret_spec.severity.upper(), bandit.HIGH)
    return bandit.Issue(
        severity=severity,
        confidence=bandit.HIGH,  # Any secret detection will now have high confidence
        cwe=issue.Cwe.HARDCODED_SECRETS,
        text=f"{secret_spec.id} ({secret_spec.description}) secret is stored in a string.",
    )


@functools.cache
def _get_database(filename: str = "new_secrets.toml") -> list[_Secret]:
    # Loads the file with regexes; uses cache
    with Path(__file__).with_name(filename).open("rb") as f:
        contents = tomllib.load(f)

    # contents is {'rules': [{'id': ..., 'description': ..., 'regex': ..., 'severity': ...}, ...]}
    rules = contents.get("rules", [])
    db = [
        _Secret(rule["id"], rule["description"], rule["regex"], rule["severity"]) for rule in rules
    ]

    # remove all the secrets that are unmatchable
    db = [secret for secret in db if secret.regex != _UNMATCHABLE_REGEX]
    return db


def _is_ignored(string_to_check: str) -> bool:
    # Check if the string matches any ignore pattern
    for pattern in _IGNORE_LIST:
        if re.search(pattern, string_to_check):
            return True
    return False


def _detect_secrets(string_to_check: str) -> list[_Secret]:
    if _is_ignored(string_to_check):
        return []

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
