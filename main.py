from fastapi import FastAPI
from html.parser import HTMLParser
from urllib.parse import urlparse

app = FastAPI()

TENANT_ID = "tenant-8uhrfqo"
EMAIL_DOMAIN = "notify-u7g09q7.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


# ============================================================
# Existing release-gate endpoint
# ============================================================

SAFE_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


def valid_sha(value):
    if not isinstance(value, str):
        return False

    return (
        len(value) == 40
        and all(c in "0123456789abcdef" for c in value)
    )


@app.get("/")
def health():
    return {
        "service": "release-gate",
        "status": "ok"
    }


@app.post("/release-gate")
def release_gate(payload: dict):
    violations = []

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")

    workflow = payload.get("workflow") or {}
    image = payload.get("image") or {}

    if workflow.get("permissions") != SAFE_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    for action in workflow.get("actions") or []:
        if action.get("owner") == "actions":
            continue

        if not valid_sha(action.get("ref")):
            violations.append("MUTABLE_ACTION")
            break

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations
    }


# ============================================================
# Action Firewall
# ============================================================

class HTMLSafetyChecker(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.unsafe = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        # Block script and iframe elements.
        if tag in {"script", "iframe"}:
            self.unsafe = True
            return

        for name, value in attrs:
            name = name.lower()

            # Block inline event handlers such as
            # onclick, onload, onerror, etc.
            if name.startswith("on"):
                self.unsafe = True
                return

            if value is None:
                continue

            # Block javascript: URLs.
            if isinstance(value, str):
                stripped = value.lstrip()
                if stripped.lower().startswith("javascript:"):
                    self.unsafe = True
                    return


def html_is_safe(value):
    if not isinstance(value, str):
        return False

    parser = HTMLSafetyChecker()

    try:
        parser.feed(value)
        parser.close()
    except Exception:
        return False

    return not parser.unsafe


def valid_top_level(payload):
    if not isinstance(payload, dict):
        return False

    allowed = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action",
    }

    # Required fields.
    required = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required.issubset(payload.keys()):
        return False

    # No unexpected fields.
    if set(payload.keys()) - allowed:
        return False

    # provenance
    if payload.get("provenance") not in {
        "trusted",
        "untrusted",
    }:
        return False

    # humanApproved
    if type(payload.get("humanApproved")) is not bool:
        return False

    # optional untrustedContent
    if "untrustedContent" in payload:
        if not isinstance(payload["untrustedContent"], str):
            return False

    # action
    action = payload.get("action")

    if not isinstance(action, dict):
        return False

    if set(action.keys()) != {"tool", "args"}:
        return False

    if not isinstance(action["tool"], str):
        return False

    if not isinstance(action["args"], dict):
        return False

    return True


def valid_string(value):
    return isinstance(value, str)


def valid_search_args(args):
    if set(args.keys()) != {"query"}:
        return False

    query = args.get("query")

    return (
        isinstance(query, str)
        and 1 <= len(query) <= 200
    )


def valid_lookup_args(args):
    if set(args.keys()) != {"tenantId", "recordId"}:
        return False

    tenant_id = args.get("tenantId")
    record_id = args.get("recordId")

    return (
        isinstance(tenant_id, str)
        and isinstance(record_id, str)
        and len(record_id) > 0
    )


def valid_email_args(args):
    if set(args.keys()) != {"to", "subject", "body"}:
        return False

    return all(
        isinstance(args.get(field), str)
        for field in ("to", "subject", "body")
    )


def email_domain_is_exact(to):
    if not isinstance(to, str):
        return False

    # Exactly one @.
    if to.count("@") != 1:
        return False

    local, domain = to.rsplit("@", 1)

    if not local or not domain:
        return False

    # Exact domain match.
    return domain.lower() == EMAIL_DOMAIN


def valid_html_args(args):
    if set(args.keys()) != {"html"}:
        return False

    return isinstance(args.get("html"), str)


@app.post("/action-firewall")
def action_firewall(payload: dict):
    # --------------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # --------------------------------------------------------
    if not valid_top_level(payload):
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    action = payload["action"]
    tool = action["tool"]
    args = action["args"]

    # --------------------------------------------------------
    # 2. TOOL ALLOWLIST
    # --------------------------------------------------------
    if tool not in ALLOWED_TOOLS:
        return {
            "decision": "block",
            "reason": "TOOL_NOT_ALLOWED"
        }

    # --------------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMA
    # --------------------------------------------------------
    if tool == "search":
        if not valid_search_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "lookup_record":
        if not valid_lookup_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "send_email":
        if not valid_email_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "render_html":
        if not valid_html_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    # --------------------------------------------------------
    # 4. TENANT SCOPE
    # --------------------------------------------------------
    if tool == "lookup_record":
        if args["tenantId"] != TENANT_ID:
            return {
                "decision": "block",
                "reason": "TENANT_SCOPE"
            }

    # --------------------------------------------------------
    # 5. EGRESS CONTROL
    # --------------------------------------------------------
    if tool == "send_email":
        if not email_domain_is_exact(args["to"]):
            return {
                "decision": "block",
                "reason": "EGRESS_DENIED"
            }

    # --------------------------------------------------------
    # 6. HUMAN APPROVAL
    # --------------------------------------------------------
    if tool == "send_email":
        if payload["humanApproved"] is not True:
            return {
                "decision": "block",
                "reason": "APPROVAL_REQUIRED"
            }

    # --------------------------------------------------------
    # 7. HTML SAFETY
    # --------------------------------------------------------
    if tool == "render_html":
        if not html_is_safe(args["html"]):
            return {
                "decision": "block",
                "reason": "UNSAFE_OUTPUT"
            }

    # --------------------------------------------------------
    # ALLOW
    # --------------------------------------------------------
    return {
        "decision": "allow",
        "reason": "ALLOW"
    }

# ============================================================
# Terraform Policy-as-Code
# ============================================================

TERRAFORM_WORKSPACE = "prod-syu8om"

REQUIRED_LABELS = {
    "owner": "student-3dfxz",
    "environment": "production",
    "cost_center": "cc-52s8",
}

ALLOWED_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

PROTECTED_DELETE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


def is_bool(value):
    return type(value) is bool


def is_string(value):
    return isinstance(value, str)


def valid_plan_schema(payload):
    if not isinstance(payload, dict):
        return False

    # Exact top-level fields
    expected_top = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if set(payload.keys()) != expected_top:
        return False

    # Top-level types
    if not is_string(payload["environment"]):
        return False

    if not is_string(payload["providerVersion"]):
        return False

    if not is_bool(payload["destroyApproved"]):
        return False

    # State object
    state = payload["state"]

    if not isinstance(state, dict):
        return False

    if set(state.keys()) != {"backend", "locked"}:
        return False

    if not is_string(state["backend"]):
        return False

    if not is_bool(state["locked"]):
        return False

    # Resource object
    resource = payload["resource"]

    if not isinstance(resource, dict):
        return False

    expected_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if set(resource.keys()) != expected_resource:
        return False

    if not is_string(resource["address"]):
        return False

    if not is_string(resource["type"]):
        return False

    if resource["action"] not in {
        "create",
        "update",
        "delete",
    }:
        return False

    # Labels must be an object.
    labels = resource["labels"]

    if not isinstance(labels, dict):
        return False

    # Label keys and values must be strings.
    for key, value in labels.items():
        if not is_string(key) or not is_string(value):
            return False

    # Secret is null OR a string.
    secret = resource["secret"]

    if secret is not None and not is_string(secret):
        return False

    if not is_bool(resource["forceDestroy"]):
        return False

    return True


def valid_provider_version(version):
    return version in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }


def valid_secret_reference(secret):
    if secret is None:
        return True

    if not isinstance(secret, str):
        return False

    return (
        secret.startswith("secret://")
        and len(secret) > len("secret://")
    )


@app.post("/terraform/plan")
def terraform_plan(payload: dict):
    # --------------------------------------------------------
    # 1. REQUEST / NESTED SCHEMA
    # --------------------------------------------------------
    if not valid_plan_schema(payload):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    environment = payload["environment"]
    state = payload["state"]
    provider_version = payload["providerVersion"]
    destroy_approved = payload["destroyApproved"]
    resource = payload["resource"]

    # --------------------------------------------------------
    # 2. ENVIRONMENT
    # --------------------------------------------------------
    if environment != TERRAFORM_WORKSPACE:
        return {
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH",
        }

    # --------------------------------------------------------
    # 3. REMOTE STATE
    # --------------------------------------------------------
    if (
        state["backend"] not in ALLOWED_BACKENDS
        or state["locked"] is not True
    ):
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE",
        }

    # --------------------------------------------------------
    # 4. PROVIDER PINNING
    # --------------------------------------------------------
    if not valid_provider_version(provider_version):
        return {
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER",
        }

    # --------------------------------------------------------
    # 5. REQUIRED LABELS
    # --------------------------------------------------------
    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS",
            }

    # --------------------------------------------------------
    # 6. SECRET
    # --------------------------------------------------------
    if not valid_secret_reference(resource["secret"]):
        return {
            "decision": "reject",
            "reason": "PLAINTEXT_SECRET",
        }

    # --------------------------------------------------------
    # 7. DESTRUCTIVE DELETE
    # --------------------------------------------------------
    if (
        resource["action"] == "delete"
        and resource["type"] in PROTECTED_DELETE_TYPES
        and destroy_approved is not True
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED",
        }

    # --------------------------------------------------------
    # 8. PRODUCTION STORAGE BUCKET FORCE DESTROY
    # --------------------------------------------------------
    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return {
            "decision": "reject",
            "reason": "FORCE_DESTROY",
        }

    # --------------------------------------------------------
    # APPROVE
    # --------------------------------------------------------
    return {
        "decision": "approve",
        "reason": "APPROVE",
    }

# ============================================================
# Model Output Sanitization
# ============================================================

import re
from html import unescape
from urllib.parse import unquote, urlparse


ALLOWED_EXTERNAL_HOSTS = {
    "cdn-x67c0s9.example",
    "app-3k95ovz.example",
}

SANITIZE_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


def sanitize_result(safe, reason):
    return {
        "safe": safe,
        "reason": reason,
    }


def decode_once(value):
    """
    Decode exactly once in this order:
      1. percent escapes
      2. HTML entities
      3. \\uXXXX escapes
    """

    decoded = unquote(value)

    # Only the entities explicitly specified by the question.
    entity_map = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    # Numeric decimal entities: &#NN;
    def numeric_decimal(match):
        try:
            return chr(int(match.group(1), 10))
        except (ValueError, OverflowError):
            return match.group(0)

    # Numeric hexadecimal entities: &#xNN;
    def numeric_hex(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    decoded = re.sub(
        r"&#([0-9]+);",
        numeric_decimal,
        decoded,
    )

    decoded = re.sub(
        r"&#x([0-9a-fA-F]+);",
        numeric_hex,
        decoded,
    )

    for entity, replacement in entity_map.items():
        decoded = decoded.replace(entity, replacement)

    # Decode literal \uXXXX escapes once.
    def unicode_escape(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        unicode_escape,
        decoded,
    )

    return decoded


def extract_urls(channel, output):
    """
    Extract URLs exactly according to the channel rules.
    """

    if channel == "html":
        # Only quoted src= and href= attributes.
        pattern = (
            r"""(?:src|href)\s*=\s*["']([^"']*)["']"""
        )
        return re.findall(
            pattern,
            output,
            flags=re.IGNORECASE,
        )

    if channel == "markdown":
        # Target inside ](...)
        pattern = r"""\]\(([^)]*)\)"""
        matches = re.findall(pattern, output)

        urls = []

        for value in matches:
            value = value.strip()

            # Markdown destinations can optionally be surrounded
            # by angle brackets.
            if (
                len(value) >= 2
                and value[0] == "<"
                and value[-1] == ">"
            ):
                value = value[1:-1]

            # Remove optional title portion:
            # (https://example "title")
            if value:
                if value.startswith(("http://", "https://", "//")):
                    parts = value.split(None, 1)
                    value = parts[0]

            urls.append(value)

        return urls

    if channel == "url":
        return [output.strip()]

    return []


def has_dangerous_scheme_text(output):
    """
    Detect javascript:, data:, vbscript:
    with optional whitespace before the colon.
    """

    return bool(
        re.search(
            r"(?:javascript|data|vbscript)\s*:",
            output,
            flags=re.IGNORECASE,
        )
    )


def url_has_dangerous_scheme(url):
    """
    An extracted URL is dangerous if it has a scheme other than
    http/https.

    Relative URLs are allowed.
    Protocol-relative URLs are treated as https.
    """

    value = url.strip()

    if not value:
        return False

    # Protocol-relative URL: //host/path
    if value.startswith("//"):
        return False

    parsed = urlparse(value)

    if parsed.scheme:
        return parsed.scheme.lower() not in {
            "http",
            "https",
        }

    return False


def has_dangerous_scheme(channel, output):
    if has_dangerous_scheme_text(output):
        return True

    for url in extract_urls(channel, output):
        if url_has_dangerous_scheme(url):
            return True

    return False


def has_external_exfil(channel, output):
    """
    Check absolute URLs only.

    Allowed:
      https://cdn-x67c0s9.example/path
      https://app-3k95ovz.example/path

    Not allowed:
      https://evil.example
      https://cdn-x67c0s9.example.attacker.example
      https://attacker.example/?next=https://allowed.example
      https://allowed@attacker.example/
      //attacker.example/path
    """

    for url in extract_urls(channel, output):
        value = url.strip()

        if not value:
            continue

        # Protocol-relative references are absolute.
        if value.startswith("//"):
            parsed = urlparse("https:" + value)
            hostname = parsed.hostname

            if hostname not in ALLOWED_EXTERNAL_HOSTS:
                return True

            continue

        parsed = urlparse(value)

        # Relative reference.
        if not parsed.scheme and not parsed.netloc:
            continue

        # Any non-http/https scheme is handled by
        # DANGEROUS_SCHEME, not EXTERNAL_EXFIL.
        if parsed.scheme.lower() not in {"http", "https"}:
            continue

        hostname = parsed.hostname

        if hostname not in ALLOWED_EXTERNAL_HOSTS:
            return True

    return False


def has_html_script_tag(output):
    """
    Opening script, iframe, object, or embed tag.
    """

    return bool(
        re.search(
            r"<\s*(?:script|iframe|object|embed)\b",
            output,
            flags=re.IGNORECASE,
        )
    )


def has_html_event_handler(output):
    """
    Detect on...= attributes, e.g.
    onclick=
    onload=
    onerror=
    """

    return bool(
        re.search(
            r"\bon[a-zA-Z0-9_-]*\s*=",
            output,
            flags=re.IGNORECASE,
        )
    )


def has_sql_metachar(output):
    if "'" in output:
        return True

    if '"' in output:
        return True

    if ";" in output:
        return True

    if "--" in output:
        return True

    if "/*" in output:
        return True

    if re.search(
        r"\bunion\b",
        output,
        flags=re.IGNORECASE,
    ):
        return True

    if re.search(
        r"\bor\s+1\s*=\s*1\b",
        output,
        flags=re.IGNORECASE,
    ):
        return True

    return False


def has_shell_metachar(output):
    if any(char in output for char in ";&|`<>"):
        return True

    if "$(" in output:
        return True

    if "${" in output:
        return True

    return False


def channel_violation(channel, output):
    """
    Apply channel rules in the specified order.
    """

    if channel == "html":
        if has_html_script_tag(output):
            return "SCRIPT_TAG"

        if has_html_event_handler(output):
            return "EVENT_HANDLER"

        if has_dangerous_scheme(channel, output):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return None

    if channel == "markdown":
        if has_dangerous_scheme(channel, output):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return None

    if channel == "url":
        if has_dangerous_scheme(channel, output):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return None

    if channel == "sql":
        if has_sql_metachar(output):
            return "SQL_METACHAR"

        return None

    if channel == "shell":
        if has_shell_metachar(output):
            return "SHELL_METACHAR"

        return None

    return None


@app.post("/sanitize-output")
def sanitize_output(payload: dict):
    # ========================================================
    # 1. INVALID_SCHEMA
    # ========================================================

    if not isinstance(payload, dict):
        return sanitize_result(
            False,
            "INVALID_SCHEMA",
        )

    if "channel" not in payload:
        return sanitize_result(
            False,
            "INVALID_SCHEMA",
        )

    if "output" not in payload:
        return sanitize_result(
            False,
            "INVALID_SCHEMA",
        )

    channel = payload["channel"]
    output = payload["output"]

    if channel not in SANITIZE_CHANNELS:
        return sanitize_result(
            False,
            "INVALID_SCHEMA",
        )

    if not isinstance(output, str):
        return sanitize_result(
            False,
            "INVALID_SCHEMA",
        )

    if len(output) > 20000:
        return sanitize_result(
            False,
            "INVALID_SCHEMA",
        )

    # ========================================================
    # 2. ENCODED_PAYLOAD
    # ========================================================

    decoded = decode_once(output)

    if decoded != output:
        decoded_violation = channel_violation(
            channel,
            decoded,
        )

        if decoded_violation is not None:
            return sanitize_result(
                False,
                "ENCODED_PAYLOAD",
            )

    # ========================================================
    # 3. ORIGINAL OUTPUT CHANNEL RULES
    # ========================================================

    violation = channel_violation(
        channel,
        output,
    )

    if violation is not None:
        return sanitize_result(
            False,
            violation,
        )

    # ========================================================
    # SAFE
    # ========================================================

    return sanitize_result(
        True,
        "SAFE",
    )
