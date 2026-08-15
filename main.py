from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any

app = FastAPI()


SAFE_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

SHA40 = set("0123456789abcdef")


def is_full_lowercase_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(c in SHA40 for c in value)
    )


class ReleaseGate(BaseModel):
    target: str
    event: str
    ref: str
    workflow: dict
    image: dict


@app.get("/")
def root():
    return {"service": "release-gate", "status": "ok"}


@app.post("/release-gate")
def release_gate(req: ReleaseGate):
    violations = []

    workflow = req.workflow
    image = req.image

    # -------------------------------------------------
    # 1. Exact least-privilege permissions
    # -------------------------------------------------
    permissions = workflow.get("permissions", {})

    if permissions != SAFE_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # -------------------------------------------------
    # 2. Pull request trigger safety
    # -------------------------------------------------
    if req.event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # -------------------------------------------------
    # 3. Complete test matrix
    # -------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # -------------------------------------------------
    # 4. Action pinning
    # -------------------------------------------------
    actions = workflow.get("actions", [])

    for action in actions:
        owner = action.get("owner")
        ref = action.get("ref")

        # Official actions/* actions may use tags
        if owner == "actions":
            continue

        # Every third-party action must use a full
        # 40-character lowercase hexadecimal SHA
        if not is_full_lowercase_sha(ref):
            violations.append("MUTABLE_ACTION")
            break

    # -------------------------------------------------
    # 5. Hardened image requirements
    # -------------------------------------------------
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

    # -------------------------------------------------
    # 6. Production-only requirements
    # -------------------------------------------------
    if req.target == "production":
        if req.event != "push" or req.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # -------------------------------------------------
    # Final decision
    # -------------------------------------------------
    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
