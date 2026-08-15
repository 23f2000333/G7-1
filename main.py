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
def action_firewall(payload):
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
