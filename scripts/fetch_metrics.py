#!/usr/bin/env python3
"""
Fetch metrics from GitHub for credential-guard tracking.

Collects data on:
- PR status and engagement
- Repository stars and forks
- Related issues and PRs
- Ecosystem trends
"""

import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List

import requests


class GitHubAPI:
    """GitHub REST API v3 wrapper."""

    def __init__(self, token: str = None, max_retries: int = 3, backoff_base: float = 1.0):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({"Authorization": f"token {self.token}"})
        self.base_url = "https://api.github.com"
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self._sleep = time.sleep

    def _get(self, url: str, params: Dict[str, Any] = None):
        """GET with exponential-backoff retry on transient network/HTTP errors."""
        last_exc = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.get(url, params=params)
                resp.raise_for_status()
                return resp
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                if attempt >= self.max_retries:
                    break
                self._sleep(self.backoff_base * (2 ** attempt))
        raise last_exc

    def get_pr(self, owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
        """Get pull request details."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        return self._get(url).json()

    def get_pr_comments(self, owner: str, repo: str, pr_number: int) -> List[Dict]:
        """Get PR comments."""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        return self._get(url, params={"per_page": 100}).json()

    def get_pr_reviews(self, owner: str, repo: str, pr_number: int) -> List[Dict]:
        """Get PR reviews."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
        return self._get(url).json()

    def get_repo(self, owner: str, repo: str) -> Dict[str, Any]:
        """Get repository details."""
        url = f"{self.base_url}/repos/{owner}/{repo}"
        return self._get(url).json()

    def search_issues(self, query: str, repo: str = None) -> List[Dict]:
        """Search for issues/PRs."""
        url = f"{self.base_url}/search/issues"
        q = query
        if repo:
            q += f" repo:{repo}"
        return self._get(url, params={"q": q, "per_page": 30}).json().get("items", [])


def collect_pr_metrics(gh: GitHubAPI, owner: str, repo: str, pr_number: int) -> Dict:
    """Collect metrics for a specific PR."""
    pr = gh.get_pr(owner, repo, pr_number)
    comments = gh.get_pr_comments(owner, repo, pr_number)
    reviews = gh.get_pr_reviews(owner, repo, pr_number)

    return {
        "state": pr["state"],
        "title": pr["title"],
        "url": pr["html_url"],
        "created_at": pr["created_at"],
        "updated_at": pr["updated_at"],
        "merged_at": pr.get("merged_at"),
        "author": pr["user"]["login"],
        "comments_count": pr["comments"],
        "review_comments_count": pr["review_comments"],
        "reactions": {
            "thumbs_up": pr.get("reactions", {}).get("+1", 0),
            "thumbs_down": pr.get("reactions", {}).get("-1", 0),
            "laugh": pr.get("reactions", {}).get("laugh", 0),
            "hooray": pr.get("reactions", {}).get("hooray", 0),
            "confused": pr.get("reactions", {}).get("confused", 0),
            "heart": pr.get("reactions", {}).get("heart", 0),
        },
        "latest_comments": [
            {
                "author": c["user"]["login"],
                "created_at": c["created_at"],
                "body": c["body"][:100],
            }
            for c in comments[-3:]  # Last 3 comments
        ],
        "review_count": len(reviews),
        "review_states": [r["state"] for r in reviews],
    }


def collect_repo_metrics(gh: GitHubAPI, owner: str, repo: str) -> Dict:
    """Collect metrics for a repository."""
    repo_data = gh.get_repo(owner, repo)

    return {
        "name": repo_data["name"],
        "full_name": repo_data["full_name"],
        "url": repo_data["html_url"],
        "description": repo_data["description"],
        "stars": repo_data["stargazers_count"],
        "forks": repo_data["forks_count"],
        "watchers": repo_data["watchers_count"],
        "open_issues": repo_data["open_issues_count"],
        "created_at": repo_data["created_at"],
        "updated_at": repo_data["updated_at"],
        "pushed_at": repo_data["pushed_at"],
        "language": repo_data["language"],
        "topics": repo_data.get("topics", []),
    }


def collect_related_issues(gh: GitHubAPI, repo_full_name: str, keywords: List[str]) -> Dict:
    """Find related issues/PRs by keyword."""
    results = {}

    for keyword in keywords[:5]:  # Limit to 5 keywords to avoid rate limiting
        query = f"{keyword} repo:{repo_full_name}"
        issues = gh.search_issues(query)
        results[keyword] = [
            {
                "number": issue["number"],
                "title": issue["title"],
                "state": issue["state"],
                "url": issue["html_url"],
                "created_at": issue["created_at"],
                "updated_at": issue.get("updated_at", ""),
                "comments": issue["comments"],
                "body": (issue.get("body") or "")[:500],
                "labels": [l.get("name", "") for l in (issue.get("labels") or [])],
            }
            for issue in issues[:5]  # Top 5 per keyword
        ]

    return results


def format_timestamp() -> str:
    """Get ISO 8601 timestamp."""
    return datetime.utcnow().isoformat() + "Z"


def main():
    """Main entry point."""
    import sys

    with open("manifest.json", "r") as f:
        manifest = json.load(f)

    gh = GitHubAPI()

    # Collect all metrics
    metrics = {
        "generated_at": format_timestamp(),
        "pr": None,
        "repo": None,
        "related_issues": None,
    }

    try:
        # Primary PR metrics
        pr_owner = manifest["tracking"]["primary_pr"]["owner"]
        pr_repo = manifest["tracking"]["primary_pr"]["repo"]
        pr_number = manifest["tracking"]["primary_pr"]["pr_number"]

        sys.stderr.write(f"Fetching PR #{pr_number} from {pr_owner}/{pr_repo}...\n")
        metrics["pr"] = collect_pr_metrics(gh, pr_owner, pr_repo, pr_number)

        # Repository metrics
        sys.stderr.write(f"Fetching repo metrics for {pr_owner}/{pr_repo}...\n")
        metrics["repo"] = collect_repo_metrics(gh, pr_owner, pr_repo)

        # Related issues
        sys.stderr.write(f"Searching for related issues...\n")
        metrics["related_issues"] = collect_related_issues(
            gh,
            f"{pr_owner}/{pr_repo}",
            manifest["search_keywords"],
        )

        # Output metrics as JSON to stdout only
        sys.stdout.write(json.dumps(metrics, indent=2))
        sys.stdout.write("\n")
        return metrics

    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        raise


if __name__ == "__main__":
    main()
