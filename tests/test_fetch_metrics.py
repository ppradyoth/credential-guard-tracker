from fetch_metrics import (
    GitHubAPI,
    collect_pr_metrics,
    collect_repo_metrics,
    collect_related_issues,
    format_timestamp,
)


class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self):
        self.headers = {}
        self.calls = []
        self.responses = []

    def get(self, url, params=None):
        self.calls.append((url, params))
        return self.responses.pop(0)


def test_github_api_sets_auth_header():
    gh = GitHubAPI(token="abc123")
    assert gh.session.headers["Authorization"] == "token abc123"


def test_github_api_no_token_no_header():
    gh = GitHubAPI(token=None)
    import os

    if not os.environ.get("GITHUB_TOKEN"):
        assert "Authorization" not in gh.session.headers


def test_search_issues_appends_repo_filter():
    gh = GitHubAPI(token="t")
    gh.session = FakeSession()
    gh.session.responses = [FakeResp({"items": [{"number": 1}]})]
    items = gh.search_issues("leak", repo="owner/repo")
    url, params = gh.session.calls[0]
    assert url.endswith("/search/issues")
    assert params["q"] == "leak repo:owner/repo"
    assert items == [{"number": 1}]


class FakeGH:
    def __init__(self, metrics):
        self._m = metrics

    def get_pr(self, owner, repo, n):
        return {
            "state": "open",
            "title": "T",
            "html_url": "https://x/pull/9",
            "created_at": "2026-06-01T00:00:00Z",
            "updated_at": "2026-06-02T00:00:00Z",
            "merged_at": None,
            "user": {"login": "me"},
            "comments": 3,
            "review_comments": 1,
            "reactions": {"+1": 2, "heart": 1},
        }

    def get_pr_comments(self, owner, repo, n):
        return [{"user": {"login": "a"}, "created_at": "2026-06-01T00:00:00Z", "body": "x" * 200}]

    def get_pr_reviews(self, owner, repo, n):
        return [{"state": "APPROVED"}]

    def get_repo(self, owner, repo):
        return {
            "name": "claude-code",
            "full_name": "anthropics/claude-code",
            "html_url": "https://github.com/anthropics/claude-code",
            "description": "Claude Code",
            "stargazers_count": 10,
            "forks_count": 2,
            "watchers_count": 900,
            "open_issues_count": 4,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2026-06-24T00:00:00Z",
            "pushed_at": "2026-06-24T00:00:00Z",
            "language": "TypeScript",
            "topics": ["ai", "cli"],
        }

    def search_issues(self, query, repo=None):
        return [
            {
                "number": 5,
                "title": "issue",
                "state": "open",
                "html_url": "https://x/issues/5",
                "created_at": "2026-06-01T00:00:00Z",
                "comments": 1,
            }
        ]


def test_collect_pr_metrics_shape():
    out = collect_pr_metrics(FakeGH(None), "o", "r", 9)
    assert out["state"] == "open"
    assert out["comments_count"] == 3
    assert out["reactions"]["thumbs_up"] == 2
    assert out["review_count"] == 1
    assert len(out["latest_comments"][0]["body"]) == 100


def test_collect_repo_metrics_shape():
    out = collect_repo_metrics(FakeGH(None), "anthropics", "claude-code")
    assert out["stars"] == 10
    assert out["forks"] == 2
    assert out["watchers"] == 900


def test_collect_related_issues_limits_keywords():
    out = collect_related_issues(FakeGH(None), "o/r", ["k1", "k2", "k3", "k4", "k5", "k6"])
    assert len(out) == 5
    assert all(len(v) <= 5 for v in out.values())


def test_format_timestamp_iso_z():
    ts = format_timestamp()
    assert ts.endswith("Z")
    assert "T" in ts
