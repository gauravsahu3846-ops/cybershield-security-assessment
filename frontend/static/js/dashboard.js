"use strict";

const elements = {
    navOpenFindings: document.getElementById("nav-open-findings"),

    refreshDashboard: document.getElementById("refresh-dashboard"),
    dashboardError: document.getElementById("dashboard-error"),

    totalFindings: document.getElementById("total-findings"),
    openFindings: document.getElementById("open-findings"),
    resolvedFindings: document.getElementById("resolved-findings"),
    totalScans: document.getElementById("total-scans"),

    severityChart: document.getElementById("severity-chart"),
    criticalCount: document.getElementById("critical-count"),
    highCount: document.getElementById("high-count"),
    mediumCount: document.getElementById("medium-count"),
    lowCount: document.getElementById("low-count"),
    infoCount: document.getElementById("info-count"),

    completedScans: document.getElementById("completed-scans"),
    failedScans: document.getElementById("failed-scans"),
    totalScanStat: document.getElementById("total-scan-stat"),
    completedBar: document.getElementById("completed-bar"),
    failedBar: document.getElementById("failed-bar"),

    findingsTable: document.getElementById("findings-table"),

    latestScans: document.getElementById(
        "latest-scans"
    ),

    scanActivityBars: document.getElementById(
        "scan-activity-bars"
    )
};

let activeRequests = [];

/* --------------------------------------------------
   DASHBOARD STATE
-------------------------------------------------- */

function setDashboardError(message = "") {
    if (!elements.dashboardError) {
        return;
    }

    elements.dashboardError.textContent = message;

    elements.dashboardError.classList.toggle(
        "hidden",
        message.length === 0
    );
}

function setLoadingState(isLoading) {
    if (!elements.refreshDashboard) {
        return;
    }

    elements.refreshDashboard.disabled = isLoading;

    elements.refreshDashboard.setAttribute(
        "aria-busy",
        String(isLoading)
    );
}

/* --------------------------------------------------
   REQUEST MANAGEMENT
-------------------------------------------------- */

function createAbortController() {
    const controller = new AbortController();

    activeRequests.push(controller);

    return controller;
}

function cleanupAbortController(controller) {
    activeRequests = activeRequests.filter(
        (item) => item !== controller
    );
}

function abortActiveRequests() {
    activeRequests.forEach((controller) => {
        controller.abort();
    });

    activeRequests = [];
}

/* --------------------------------------------------
   API
-------------------------------------------------- */

async function fetchJson(url, signal) {
    const response = await fetch(url, {
        method: "GET",
        headers: {
            Accept: "application/json"
        },
        credentials: "same-origin",
        cache: "no-store",
        signal
    });

    if (!response.ok) {
        throw new Error(
            `Request failed with status ${response.status}`
        );
    }

    const data = await response.json();

    if (!data || typeof data !== "object") {
        throw new Error(
            "Invalid server response."
        );
    }

    return data;
}

/* --------------------------------------------------
   NORMALIZATION
-------------------------------------------------- */

function normalizeSeverity(severity) {
    const allowed = new Set([
        "critical",
        "high",
        "medium",
        "low",
        "info"
    ]);

    const value = String(
        severity || "info"
    ).toLowerCase();

    return allowed.has(value)
        ? value
        : "info";
}

function normalizeStatus(status) {
    const allowed = new Set([
        "open",
        "resolved",
        "false_positive",
        "accepted_risk"
    ]);

    const value = String(
        status || "open"
    ).toLowerCase();

    return allowed.has(value)
        ? value
        : "open";
}

function formatStatus(status) {
    const labels = {
        open: "Open",
        resolved: "Resolved",
        false_positive: "False Positive",
        accepted_risk: "Accepted Risk"
    };

    return (
        labels[normalizeStatus(status)] ||
        "Open"
    );
}

function formatSeverity(severity) {
    const value = normalizeSeverity(severity);

    return (
        value.charAt(0).toUpperCase() +
        value.slice(1)
    );
}

function formatCwe(value) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "—";
    }

    const text = String(value).trim();

    if (!text) {
        return "—";
    }

    return text.toUpperCase().startsWith("CWE-")
        ? text.toUpperCase()
        : `CWE-${text}`;
}

/* --------------------------------------------------
   LATEST SCANS
-------------------------------------------------- */

function formatScanType(scanType) {
    const value = String(
        scanType || "unknown"
    ).trim().toLowerCase();

    const labels = {
        nmap: "Nmap Scan",
        full: "Full Assessment"
    };

    return labels[value] || (
        value
            ? value.charAt(0).toUpperCase() + value.slice(1)
            : "Security Scan"
    );
}

function formatScanTime(value) {
    if (!value) {
        return "Time unavailable";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "Time unavailable";
    }

    return new Intl.DateTimeFormat(
        undefined,
        {
            day: "2-digit",
            month: "short",
            hour: "2-digit",
            minute: "2-digit"
        }
    ).format(date);
}

function getScanStatusClass(status) {
    const value = String(
        status || "pending"
    ).toLowerCase();

    if (value === "completed") {
        return "success";
    }

    if (value === "failed") {
        return "danger";
    }

    return "pending";
}

function getScanStatusIcon(status) {
    const value = String(
        status || "pending"
    ).toLowerCase();

    if (value === "completed") {
        return "✓";
    }

    if (value === "failed") {
        return "!";
    }

    return "•";
}

function updateLatestScans(scans) {
    const container = elements.latestScans;

    if (!container) {
        return;
    }

    container.replaceChildren();

    if (!Array.isArray(scans) || scans.length === 0) {
        const empty = document.createElement("div");
        empty.className = "table-empty";
        empty.textContent = "No scan history available.";
        container.appendChild(empty);
        return;
    }

    scans.slice(0, 4).forEach((scan) => {
        const item = document.createElement("div");
        item.className = "latest-scan";

        const statusClass = getScanStatusClass(
            scan.status
        );

        const icon = document.createElement("span");
        icon.className =
            `scan-status-icon ${statusClass}`;
        icon.setAttribute("aria-hidden", "true");
        icon.textContent =
            getScanStatusIcon(scan.status);

        const details = document.createElement("div");

        const title = document.createElement("strong");
        title.textContent =
            scan.target_name || "Unknown target";

        const meta = document.createElement("span");
        meta.textContent =
            `${formatScanType(scan.scan_type)} • ${formatScanTime(scan.started_at || scan.created_at)}`;

        details.append(
            title,
            meta
        );

        const state = document.createElement("span");
        state.className =
            `scan-state ${statusClass}`;
        state.textContent =
            String(scan.status || "pending")
                .replace("_", " ")
                .replace(/^\w/, (char) => char.toUpperCase());

        item.append(
            icon,
            details,
            state
        );

        container.appendChild(item);
    });
}

/* --------------------------------------------------
   SUMMARY
-------------------------------------------------- */

function updateSummary(summary) {
    const findings =
        summary?.findings || {};

    const scans =
        summary?.scans || {};

    const severity =
        summary?.severity || {};

    const totalFindings =
        Number(findings.total) || 0;

    const openFindings =
        Number(findings.open) || 0;

    const resolvedFindings =
        Number(findings.resolved) || 0;

    const totalScans =
        Number(scans.total) || 0;

    if (elements.totalFindings) {
        elements.totalFindings.textContent =
            String(totalFindings);
    }

    if (elements.openFindings) {
        elements.openFindings.textContent =
            String(openFindings);
    }

    if (elements.resolvedFindings) {
        elements.resolvedFindings.textContent =
            String(resolvedFindings);
    }

    if (elements.totalScans) {
        elements.totalScans.textContent =
            String(totalScans);
    }

    if (elements.navOpenFindings) {
        elements.navOpenFindings.textContent =
            String(openFindings);
    }

    updateSeverityCounts(severity);
    updateSeverityChart(severity);
    updateScanProgress(scans);
}

/* --------------------------------------------------
   SEVERITY COUNTS
-------------------------------------------------- */

function updateSeverityCounts(severity) {
    const values = {
        critical:
            Number(severity?.critical) || 0,

        high:
            Number(severity?.high) || 0,

        medium:
            Number(severity?.medium) || 0,

        low:
            Number(severity?.low) || 0,

        info:
            Number(severity?.info) || 0
    };

    if (elements.criticalCount) {
        elements.criticalCount.textContent =
            String(values.critical);
    }

    if (elements.highCount) {
        elements.highCount.textContent =
            String(values.high);
    }

    if (elements.mediumCount) {
        elements.mediumCount.textContent =
            String(values.medium);
    }

    if (elements.lowCount) {
        elements.lowCount.textContent =
            String(values.low);
    }

    if (elements.infoCount) {
        elements.infoCount.textContent =
            String(values.info);
    }
}

/* --------------------------------------------------
   SEVERITY CHART
-------------------------------------------------- */

function updateSeverityChart(severity) {
    if (!elements.severityChart) {
        return;
    }

    const values = [
        {
            label: "Critical",
            value:
                Number(severity?.critical) || 0,
            className: "critical"
        },
        {
            label: "High",
            value:
                Number(severity?.high) || 0,
            className: "high"
        },
        {
            label: "Medium",
            value:
                Number(severity?.medium) || 0,
            className: "medium"
        },
        {
            label: "Low",
            value:
                Number(severity?.low) || 0,
            className: "low"
        },
        {
            label: "Info",
            value:
                Number(severity?.info) || 0,
            className: "info"
        }
    ];

    const total = values.reduce(
        (sum, item) =>
            sum + item.value,
        0
    );

    elements.severityChart.replaceChildren();

    const container =
        document.createElement("div");

    container.className =
        "severity-bars";

    values.forEach((item) => {
        const row =
            document.createElement("div");

        row.className =
            "severity-bar-row";

        const label =
            document.createElement("div");

        label.className =
            "severity-bar-label";

        const name =
            document.createElement("span");

        name.textContent =
            item.label;

        const count =
            document.createElement("strong");

        count.textContent =
            String(item.value);

        label.append(
            name,
            count
        );

        const track =
            document.createElement("div");

        track.className =
            "severity-bar-track";

        const bar =
            document.createElement("progress");

        bar.className =
            `severity-progress ${item.className}`;

        bar.max = 100;

        const percentage =
            total > 0
                ? (item.value / total) * 100
                : 0;

        bar.value =
            percentage;

        bar.setAttribute(
            "aria-label",
            `${item.label}: ${item.value} findings`
        );

        track.appendChild(bar);

        row.append(
            label,
            track
        );

        container.appendChild(row);
    });

    elements.severityChart.appendChild(
        container
    );
}

/* --------------------------------------------------
   SCAN PROGRESS
-------------------------------------------------- */

function updateScanProgress(scans) {
    const total =
        Number(scans?.total) || 0;

    const completed =
        Number(scans?.completed) || 0;

    const failed =
        Number(scans?.failed) || 0;

    const completedPercent =
        total > 0
            ? Math.min(
                (completed / total) * 100,
                100
            )
            : 0;

    const failedPercent =
        total > 0
            ? Math.min(
                (failed / total) * 100,
                100
            )
            : 0;

    if (elements.completedScans) {
        elements.completedScans.textContent =
            String(completed);
    }

    if (elements.failedScans) {
        elements.failedScans.textContent =
            String(failed);
    }

    if (elements.totalScanStat) {
        elements.totalScanStat.textContent =
            String(total);
    }

    updateProgressElement(
        elements.completedBar,
        completedPercent
    );

    updateProgressElement(
        elements.failedBar,
        failedPercent
    );
}

function updateProgressElement(
    element,
    percentage
) {
    if (!element) {
        return;
    }

    const value =
        Math.max(
            0,
            Math.min(
                Number(percentage) || 0,
                100
            )
        );

    element.style.setProperty(
        "--progress-width",
        `${value}%`
    );

    element.setAttribute(
        "aria-valuenow",
        value.toFixed(1)
    );
}

/* --------------------------------------------------
   FINDINGS
-------------------------------------------------- */

function extractFindings(payload) {
    if (Array.isArray(payload)) {
        return payload;
    }

    if (
        Array.isArray(
            payload?.findings
        )
    ) {
        return payload.findings;
    }

    if (
        Array.isArray(
            payload?.data
        )
    ) {
        return payload.data;
    }

    return [];
}

function updateFindings(findings) {
    if (!elements.findingsTable) {
        return;
    }

    elements.findingsTable.replaceChildren();

    if (
        !Array.isArray(findings) ||
        findings.length === 0
    ) {
        const row =
            document.createElement("tr");

        const cell =
            document.createElement("td");

        cell.colSpan = 6;

        cell.className =
            "table-empty";

        cell.textContent =
            "No findings available.";

        row.appendChild(cell);

        elements.findingsTable.appendChild(
            row
        );

        return;
    }

    findings
        .slice(0, 10)
        .forEach((finding) => {
            const row =
                document.createElement("tr");

            const idCell =
                document.createElement("td");

            idCell.textContent =
                finding.id !== undefined
                    ? `#${finding.id}`
                    : "—";

            const titleCell =
                document.createElement("td");

            titleCell.textContent =
                finding.title ||
                finding.name ||
                finding.description ||
                "Untitled finding";

            const severityCell =
                document.createElement("td");

            const severity =
                normalizeSeverity(
                    finding.severity
                );

            const severityBadge =
                document.createElement("span");

            severityBadge.className =
                `severity-badge severity-${severity}`;

            severityBadge.textContent =
                formatSeverity(
                    severity
                );

            severityCell.appendChild(
                severityBadge
            );

            const statusCell =
                document.createElement("td");

            const status =
                normalizeStatus(
                    finding.status
                );

            const statusBadge =
                document.createElement("span");

            statusBadge.className =
                `status-badge status-${status}`;

            statusBadge.textContent =
                formatStatus(
                    status
                );

            statusCell.appendChild(
                statusBadge
            );

            const cweCell =
                document.createElement("td");

            cweCell.textContent =
                formatCwe(
                    finding.cwe
                );

            const actionCell =
                document.createElement("td");

            const actionButton =
                document.createElement("button");

            actionButton.type =
                "button";

            actionButton.className =
                "text-button";

            actionButton.textContent =
                "View";

            if (
                finding.id !== undefined
            ) {
                actionButton.dataset.findingId =
                    String(finding.id);
            }

            actionCell.appendChild(
                actionButton
            );

            row.append(
                idCell,
                titleCell,
                severityCell,
                statusCell,
                cweCell,
                actionCell
            );

            elements.findingsTable.appendChild(
                row
            );
        });
}

/* --------------------------------------------------
   SCAN ACTIVITY
-------------------------------------------------- */

function updateScanActivity(scans) {
    const container =
        elements.scanActivityBars;

    if (!container) {
        return;
    }

    container.replaceChildren();

    if (
        !Array.isArray(scans) ||
        scans.length === 0
    ) {
        return;
    }

    /*
     * API returns newest first.
     * Reverse so the chart reads
     * chronologically from left to right.
     */
    const recentScans =
        scans
            .slice(0, 12)
            .reverse();

    /*
     * Calculate bar heights from
     * real scan duration.
     *
     * If duration is unavailable,
     * use a neutral baseline.
     */
    const durations =
        recentScans.map((scan) => {
            const start =
                Date.parse(
                    scan.started_at || ""
                );

            const end =
                Date.parse(
                    scan.completed_at || ""
                );

            if (
                Number.isNaN(start) ||
                Number.isNaN(end) ||
                end < start
            ) {
                return 1;
            }

            return Math.max(
                (end - start) / 1000,
                1
            );
        });

    const maxDuration =
        Math.max(
            ...durations,
            1
        );

    recentScans.forEach(
        (scan, index) => {
            const bar =
                document.createElement("span");

            const status =
                String(
                    scan.status ||
                    "unknown"
                ).toLowerCase();

            if (
                status === "completed"
            ) {
                bar.classList.add(
                    "activity-completed"
                );
            } else if (
                status === "failed"
            ) {
                bar.classList.add(
                    "activity-failed"
                );
            } else {
                bar.classList.add(
                    "activity-pending"
                );
            }

            const duration =
                durations[index];

            /*
             * Keep bars readable even when
             * scan durations are very close.
             */
            const height =
                22 +
                (
                    duration /
                    maxDuration
                ) * 58;

            bar.style.setProperty(
                "--activity-height",
                `${height}%`
            );

            const scanId =
                scan.id !== undefined
                    ? `#${scan.id}`
                    : "Unknown";

            const targetName =
                scan.target_name ||
                "Unknown target";

            const scanType =
                scan.scan_type ||
                "unknown";

            const statusLabel =
                status.charAt(0).toUpperCase() +
                status.slice(1);

            bar.setAttribute(
                "title",
                `Scan ${scanId} • ${targetName} • ${scanType} • ${statusLabel}`
            );

            bar.setAttribute(
                "aria-label",
                `Scan ${scanId}, ${targetName}, ${scanType}, ${statusLabel}`
            );

            container.appendChild(
                bar
            );
        }
    );
}

/* --------------------------------------------------
   API LOADERS
-------------------------------------------------- */

async function loadSummary() {
    const controller =
        createAbortController();

    try {
        const payload =
            await fetchJson(
                "/api/dashboard/summary",
                controller.signal
            );

        if (
            payload.status !==
            "success"
        ) {
            throw new Error(
                "Dashboard summary request failed."
            );
        }

        updateSummary(
            payload.summary || {}
        );
    } finally {
        cleanupAbortController(
            controller
        );
    }
}

async function loadFindings() {
    const controller =
        createAbortController();

    try {
        const payload =
            await fetchJson(
                "/api/findings/",
                controller.signal
            );

        updateFindings(
            extractFindings(payload)
        );
    } finally {
        cleanupAbortController(
            controller
        );
    }
}

async function loadScanActivity() {
    const controller =
        createAbortController();

    try {
        const payload =
            await fetchJson(
                "/api/scans/",
                controller.signal
            );

        if (
            payload.status !==
            "success"
        ) {
            throw new Error(
                "Scan activity request failed."
            );
        }

        const scans =
            Array.isArray(payload.scans)
                ? payload.scans
                : [];

        updateScanActivity(scans);
        updateLatestScans(scans);
    } finally {
        cleanupAbortController(
            controller
        );
    }
}
/* --------------------------------------------------
   DASHBOARD LOAD
-------------------------------------------------- */

async function loadDashboard() {
    abortActiveRequests();

    setLoadingState(true);

    setDashboardError("");

    try {
        await Promise.all([
            loadSummary(),
            loadFindings(),
            loadScanActivity()
        ]);
    } catch (error) {
        if (
            error?.name ===
            "AbortError"
        ) {
            return;
        }

        console.error(
            "CyberShield dashboard load failed:",
            error
        );

        setDashboardError(
            "Unable to load dashboard data. Please try again."
        );
    } finally {
        setLoadingState(false);
    }
}

/* --------------------------------------------------
   EVENTS
-------------------------------------------------- */

function initializeDashboard() {
    if (
        elements.refreshDashboard
    ) {
        elements.refreshDashboard.addEventListener(
            "click",
            () => {
                loadDashboard();
            }
        );
    }

    if (
        elements.findingsTable
    ) {
        elements.findingsTable.addEventListener(
            "click",
            (event) => {
                const button =
                    event.target.closest(
                        "button[data-finding-id]"
                    );

                if (!button) {
                    return;
                }

                const findingId =
                    button.dataset.findingId;

                if (!findingId) {
                    return;
                }

                window.location.hash =
                    `finding-${encodeURIComponent(
                        findingId
                    )}`;
            }
        );
    }

    loadDashboard();
}

/* --------------------------------------------------
   BOOTSTRAP
-------------------------------------------------- */

if (
    document.readyState ===
    "loading"
) {
    document.addEventListener(
        "DOMContentLoaded",
        initializeDashboard,
        { once: true }
    );
} else {
    initializeDashboard();
}
