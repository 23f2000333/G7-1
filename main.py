from fastapi import FastAPI
from typing import Any

app = FastAPI()


SAFE_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


def valid_sha(ref: Any) -> bool:
    if not isinstance(ref, str):
        return False

    if len(ref) != 40:
        return False

    return all(c in "0123456789abcdef" for c in ref)


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

    # 1. Exact least-privilege permissions
    permissions = workflow.get("permissions")

    if permissions != SAFE_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull request must use pull_request
    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests, matrix and failFast
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    actions = workflow.get("actions") or []

    for action in actions:
        owner = action.get("owner")
        action_ref = action.get("ref")

        # actions/* may use tags such as v4
        if owner == "actions":
            continue

        # Every third-party action must use
        # a 40-character lowercase hexadecimal SHA.
        if not valid_sha(action_ref):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Image hardening
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

    # 6. Production requirements
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if len(violations) == 0 else "block",
        "violations": violations
    }
