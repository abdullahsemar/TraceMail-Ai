const API_BASE = "http://localhost:8000/api";

export async function fetchStats() {
  const res = await fetch(`${API_BASE}/dashboard/stats`);
  return res.json();
}

export async function fetchEmails({ page = 1, pageSize = 50, severity = null, source = null, search = null } = {}) {
  let url = `${API_BASE}/emails?page=${page}&page_size=${pageSize}`;
  if (severity && severity !== 'ALL') url += `&severity=${encodeURIComponent(severity)}`;
  if (source && source !== 'ALL') url += `&source=${encodeURIComponent(source)}`;
  if (search && search.trim()) url += `&search=${encodeURIComponent(search.trim())}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchEmailDetails(emailId) {
  const res = await fetch(`${API_BASE}/emails/${emailId}`);
  return res.json();
}

export async function fetchCases() {
  const res = await fetch(`${API_BASE}/cases`);
  return res.json();
}

// ----------------- REVIEW QUEUE API (REPLACES QUARANTINE) -----------------
export async function fetchReviewQueue() {
  const res = await fetch(`${API_BASE}/review-queue`);
  return res.json();
}

export async function updateCaseReviewStatus(caseId, payload) {
  const res = await fetch(`${API_BASE}/review-queue/${caseId}/review`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Failed to update review status" }));
    throw new Error(err.detail || "Failed to update review status");
  }
  return res.json();
}

export async function submitAnalystFeedback(caseId, payload) {
  const res = await fetch(`${API_BASE}/cases/${caseId}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Failed to submit analyst feedback" }));
    throw new Error(err.detail || "Failed to submit analyst feedback");
  }
  return res.json();
}

export async function fetchCampaigns() {
  const res = await fetch(`${API_BASE}/campaigns`);
  return res.json();
}

export async function fetchIocs() {
  const res = await fetch(`${API_BASE}/threat-intel/iocs`);
  return res.json();
}

export async function fetchAuditEvents() {
  const res = await fetch(`${API_BASE}/audit/events`);
  return res.json();
}

export async function verifyAuditChain() {
  const res = await fetch(`${API_BASE}/audit/verify-chain`);
  return res.json();
}

export async function fetchReports() {
  const res = await fetch(`${API_BASE}/reports`);
  return res.json();
}

export async function generateReport() {
  const res = await fetch(`${API_BASE}/reports/generate`, { method: "POST" });
  return res.json();
}

export async function fetchConnectors() {
  const res = await fetch(`${API_BASE}/connectors`);
  return res.json();
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

// ----------------- SMTP GATEWAY & DOWNSTREAM DIAGNOSTICS -----------------
export async function fetchSmtpStatus() {
  const res = await fetch(`${API_BASE}/smtp/status`);
  return res.json();
}

export async function testDownstreamSmtp() {
  const res = await fetch(`${API_BASE}/smtp/test-downstream`, {
    method: "POST"
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Downstream SMTP test failed" }));
    throw new Error(err.detail || "Downstream SMTP test failed");
  }
  return res.json();
}

// ----------------- GMAIL CONNECTOR API -----------------
export async function fetchGmailStatus() {
  const res = await fetch(`${API_BASE}/connectors/gmail/status`);
  return res.json();
}

export async function getGmailAuthUrl() {
  const res = await fetch(`${API_BASE}/connectors/gmail/auth`);
  return res.json();
}

export async function startGmailWatch(topic = null) {
  const res = await fetch(`${API_BASE}/connectors/gmail/watch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ topic })
  });
  return res.json();
}

export async function pollGmailNow() {
  const res = await fetch(`${API_BASE}/connectors/gmail/poll`, {
    method: "POST"
  });
  return res.json();
}

export async function syncGmailInbox(limit = 25) {
  const res = await fetch(`${API_BASE}/connectors/gmail/sync`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ limit })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Gmail sync failed" }));
    throw new Error(err.detail || "Gmail sync failed");
  }
  return res.json();
}

export async function disconnectGmail() {
  const res = await fetch(`${API_BASE}/connectors/gmail/disconnect`, {
    method: "POST"
  });
  return res.json();
}

// ----------------- TELEGRAM NOTIFICATIONS API -----------------
export async function testTelegramConnection() {
  const res = await fetch(`${API_BASE}/notifications/telegram/test`, {
    method: "POST"
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Telegram test failed" }));
    throw new Error(err.detail || "Telegram test failed");
  }
  return res.json();
}
