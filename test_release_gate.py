import json
import urllib.request


URL = "http://127.0.0.1:8000/release-gate"


def call(payload):
    request = urllib.request.Request(
        URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def safe_preview():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature/test",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none"
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {
                    "owner": "actions",
                    "name": "checkout",
                    "ref": "v4"
                },
                {
                    "owner": "thirdparty",
                    "name": "example",
                    "ref": "0123456789abcdef0123456789abcdef01234567"
                }
            ]
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True
        }
    }


def unsafe_preview():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/test",
        "workflow": {
            "trigger": "pull_request_target",
            "permissions": {
                "contents": "write",
                "packages": "write",
                "id-token": "none"
            },
            "testsPassed": False,
            "matrixComplete": False,
            "failFast": True,
            "actions": [
                {
                    "owner": "someone",
                    "name": "bad-action",
                    "ref": "v1"
                }
            ]
        },
        "image": {
            "multiStage": False,
            "runsAsRoot": True,
            "secretMode": "copy",
            "criticalVulnerabilities": 2,
            "digestPinned": False
        }
    }


def production_without_approval():
    payload = safe_preview()

    payload["target"] = "production"
    payload["event"] = "push"
    payload["ref"] = "refs/heads/main"

    payload["workflow"]["environmentApproval"] = False

    return payload


def main():
    # Safe case
    result = call(safe_preview())

    print("SAFE TEST")
    print(result)

    assert result["decision"] == "promote"
    assert result["violations"] == []

    # Multi-failure case
    result = call(unsafe_preview())

    print("UNSAFE TEST")
    print(result)

    expected = {
        "EXCESS_PERMISSION",
        "UNSAFE_PR_TRIGGER",
        "TESTS_INCOMPLETE",
        "MUTABLE_ACTION",
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    }

    assert result["decision"] == "block"
    assert set(result["violations"]) == expected

    # Production approval case
    result = call(production_without_approval())

    print("PRODUCTION TEST")
    print(result)

    assert result["decision"] == "block"
    assert result["violations"] == ["APPROVAL_REQUIRED"]

    print("ALL RELEASE-GATE TESTS PASSED")


if __name__ == "__main__":
    main()
