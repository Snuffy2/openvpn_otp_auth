"""Repository-specific release gate identities for shared contract tests."""

GATES = (
    {
        "workflow": "pytest_check.yml",
        "job": "pull-request-tests",
        "product": "pytest",
        "required_check": "pytest_check.yml::pytest check and post coverage",
    },
    {
        "workflow": "prek-autofix-review.yml",
        "job": "review",
        "product": "prek",
        "required_check": "prek-autofix-review.yml::review",
    },
)
