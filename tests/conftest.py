import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))


SAMPLE_METRICS = {
    "generated_at": "2026-06-25T08:00:00Z",
    "pr": {
        "state": "open",
        "title": "Add credential-guard plugin",
        "url": "https://github.com/anthropics/claude-code/pull/62099",
        "created_at": "2026-05-01T10:00:00Z",
        "updated_at": "2026-06-24T12:00:00Z",
        "merged_at": None,
        "author": "ppradyoth",
        "comments_count": 12,
        "review_comments_count": 4,
        "reactions": {"thumbs_up": 7, "heart": 3},
        "latest_comments": [
            {"author": "reviewer", "created_at": "2026-06-24T11:00:00Z", "body": "Looks good"},
        ],
        "review_count": 2,
        "review_states": ["APPROVED", "COMMENTED"],
    },
    "repo": {
        "name": "claude-code",
        "full_name": "anthropics/claude-code",
        "url": "https://github.com/anthropics/claude-code",
        "description": "Claude Code",
        "stars": 12345,
        "forks": 678,
        "watchers": 900,
        "open_issues": 42,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2026-06-24T00:00:00Z",
        "pushed_at": "2026-06-24T00:00:00Z",
        "language": "TypeScript",
        "topics": ["ai", "cli", "security"],
    },
    "related_issues": {
        "credential": [
            {
                "number": 100,
                "title": "Secrets leak in logs",
                "state": "open",
                "url": "https://github.com/anthropics/claude-code/issues/100",
                "created_at": "2026-06-01T00:00:00Z",
                "comments": 5,
            }
        ],
        "secrets": [],
    },
}
