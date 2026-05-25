/**
 * Credential Guard Tracker Dashboard
 * Fetches and displays GitHub issues and PR data
 */

const CONFIG = {
    prOwner: 'anthropics',
    prRepo: 'claude-code',
    prNumber: 62099,
    trackerOwner: 'ppradyoth',
    trackerRepo: 'credential-guard-tracker',
};

const API_BASE = 'https://api.github.com';

/**
 * Fetch JSON from GitHub API
 */
async function fetchGitHub(endpoint) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`);
        if (!response.ok) {
            throw new Error(`GitHub API error: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Fetch error:', error);
        return null;
    }
}

/**
 * Format timestamp to readable date
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

/**
 * Format timestamp to relative time
 */
function timeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);

    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
    return formatDate(dateString);
}

/**
 * Fetch PR data
 */
async function fetchPRData() {
    const endpoint = `/repos/${CONFIG.prOwner}/${CONFIG.prRepo}/pulls/${CONFIG.prNumber}`;
    return await fetchGitHub(endpoint);
}

/**
 * Fetch repo data
 */
async function fetchRepoData() {
    const endpoint = `/repos/${CONFIG.prOwner}/${CONFIG.prRepo}`;
    return await fetchGitHub(endpoint);
}

/**
 * Fetch tracker issues (daily reports)
 */
async function fetchTrackerIssues() {
    const endpoint = `/repos/${CONFIG.trackerOwner}/${CONFIG.trackerRepo}/issues?state=open&labels=daily-report&per_page=10`;
    return await fetchGitHub(endpoint);
}

/**
 * Search for related issues by keyword
 */
async function searchRelatedIssues() {
    const keywords = ['credential', 'secret', 'hardcoded', 'api_key', 'security'];
    const allIssues = {};

    for (const keyword of keywords) {
        const query = encodeURIComponent(`${keyword} repo:${CONFIG.prOwner}/${CONFIG.prRepo}`);
        const endpoint = `/search/issues?q=${query}&per_page=5`;
        const result = await fetchGitHub(endpoint);
        if (result && result.items) {
            allIssues[keyword] = result.items;
        }
    }

    return allIssues;
}

/**
 * Render PR card
 */
function renderPRCard(pr) {
    const statusClass = pr.state === 'open' ? 'open' : 'closed';
    const statusText = pr.state === 'open' ? 'Open' : 'Merged';

    const html = `
        <div class="pr-header">
            <h3 class="pr-title">#${pr.number}: ${pr.title}</h3>
            <span class="pr-status ${statusClass}">${statusText}</span>
        </div>

        <div class="pr-stats">
            <div class="pr-stat">
                <span class="pr-stat-label">Comments</span>
                <span class="pr-stat-value">${pr.comments}</span>
            </div>
            <div class="pr-stat">
                <span class="pr-stat-label">Reviews</span>
                <span class="pr-stat-value">${pr.review_comments}</span>
            </div>
            <div class="pr-stat">
                <span class="pr-stat-label">👍 Reactions</span>
                <span class="pr-stat-value">${pr.reactions['+1'] || 0}</span>
            </div>
        </div>

        <div class="pr-meta">
            <span>Created: ${formatDate(pr.created_at)}</span>
            <span>Updated: ${timeAgo(pr.updated_at)}</span>
            <a href="${pr.html_url}" target="_blank" class="pr-link">View on GitHub →</a>
        </div>
    `;

    document.getElementById('prCard').innerHTML = html;
}

/**
 * Render daily reports list
 */
function renderReports(issues) {
    if (!issues || issues.length === 0) {
        document.getElementById('reportsList').innerHTML = '<p class="error">No reports found</p>';
        return;
    }

    const html = issues.map(issue => `
        <div class="report-item">
            <span class="report-date">${formatDate(issue.created_at)}</span>
            <a href="${issue.html_url}" target="_blank" class="report-link">
                ${issue.title} →
            </a>
        </div>
    `).join('');

    document.getElementById('reportsList').innerHTML = html;
}

/**
 * Render related issues
 */
function renderIssues(issuesByKeyword) {
    const html = Object.entries(issuesByKeyword)
        .filter(([_, issues]) => issues && issues.length > 0)
        .map(([keyword, issues]) => `
            <div class="issues-by-keyword">
                <h3 class="keyword-title">${keyword.charAt(0).toUpperCase() + keyword.slice(1)}</h3>
                <div class="issue-list">
                    ${issues.map(issue => `
                        <div class="issue-item">
                            <div class="issue-header">
                                <span class="issue-number">#${issue.number}</span>
                                <a href="${issue.html_url}" target="_blank" class="issue-title">
                                    ${issue.title}
                                </a>
                            </div>
                            <div class="issue-meta">
                                <span>${issue.state === 'open' ? '🔵 Open' : '✅ Closed'}</span>
                                <span>${issue.comments} comments</span>
                                <span>${timeAgo(issue.created_at)}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `).join('');

    document.getElementById('issuesContainer').innerHTML = html || '<p class="error">No related issues found</p>';
}

/**
 * Update metrics
 */
function updateMetrics(pr, repo, issues) {
    // PR State
    const stateEmoji = pr.state === 'open' ? '🟢' : '🟣';
    document.getElementById('prState').textContent = `${stateEmoji} ${pr.state.toUpperCase()}`;

    // Comments
    document.getElementById('prComments').textContent = pr.comments.toString();

    // Stars
    document.getElementById('repoStars').textContent = `${(repo.stargazers_count / 1000).toFixed(1)}K`;

    // Related Issues Count
    const issueCount = Object.values(issues).reduce((sum, arr) => sum + (arr ? arr.length : 0), 0);
    document.getElementById('relatedIssues').textContent = issueCount.toString();

    // Last Updated
    const now = new Date();
    document.getElementById('lastUpdated').textContent = now.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    });
}

/**
 * Initialize dashboard
 */
async function initialize() {
    try {
        // Fetch all data
        const [pr, repo, trackerIssues, relatedIssues] = await Promise.all([
            fetchPRData(),
            fetchRepoData(),
            fetchTrackerIssues(),
            searchRelatedIssues()
        ]);

        if (!pr || !repo) {
            throw new Error('Failed to fetch required data');
        }

        // Render sections
        renderPRCard(pr);
        renderReports(trackerIssues);
        renderIssues(relatedIssues);
        updateMetrics(pr, repo, relatedIssues);

    } catch (error) {
        console.error('Initialization error:', error);
        document.getElementById('prCard').innerHTML = `<p class="error">Error loading data: ${error.message}</p>`;
        document.getElementById('reportsList').innerHTML = `<p class="error">Error loading reports</p>`;
        document.getElementById('issuesContainer').innerHTML = `<p class="error">Error loading issues</p>`;
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}
