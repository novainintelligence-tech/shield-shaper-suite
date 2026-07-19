/* global chrome */

const outputEl = document.getElementById("output");
const summaryEl = document.getElementById("summary");
const statusEl = document.getElementById("status");

let lastPayload = null;

function setStatus(msg, ok) {
  statusEl.textContent = msg || "";
  statusEl.className = "status " + (ok === true ? "ok" : ok === false ? "err" : "");
}

function serializeCookieString(cookies) {
  return cookies.map((c) => `${c.name}=${c.value}`).join("; ");
}

async function captureTab(tab) {
  if (!tab.url || !/^https?:/i.test(tab.url)) {
    return { skipped: true, reason: "non-http tab", url: tab.url || "" };
  }
  const url = new URL(tab.url);
  const origin = url.origin;

  // Cookies (includes HttpOnly + Secure attrs)
  const rawCookies = await chrome.cookies.getAll({ url: tab.url });
  const cookies = rawCookies.map((c) => ({
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    secure: c.secure,
    httpOnly: c.httpOnly,
    sameSite: c.sameSite,
    session: c.session,
    expirationDate: c.expirationDate || null,
  }));

  // Storage via executeScript
  let storage = { localStorage: {}, sessionStorage: {}, href: tab.url, ua: null };
  try {
    const [{ result } = {}] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const dump = (s) => {
          const out = {};
          try {
            for (let i = 0; i < s.length; i++) {
              const k = s.key(i);
              if (k != null) out[k] = s.getItem(k) ?? "";
            }
          } catch (_) {}
          return out;
        };
        return {
          href: location.href,
          ua: navigator.userAgent,
          localStorage: dump(window.localStorage),
          sessionStorage: dump(window.sessionStorage),
        };
      },
    });
    if (result) storage = result;
  } catch (e) {
    // scripting may fail on chrome:// or restricted pages
  }

  return {
    href: storage.href || tab.url,
    origin,
    title: tab.title || null,
    ua: storage.ua || null,
    at: new Date().toISOString(),
    cookies: serializeCookieString(cookies),
    cookieDetails: cookies,
    localStorage: storage.localStorage || {},
    sessionStorage: storage.sessionStorage || {},
  };
}

function summarize(snapshots) {
  const httpOnly = snapshots.reduce(
    (n, s) => n + (s.cookieDetails || []).filter((c) => c.httpOnly).length,
    0
  );
  const totalCookies = snapshots.reduce((n, s) => n + (s.cookieDetails || []).length, 0);
  const ls = snapshots.reduce((n, s) => n + Object.keys(s.localStorage || {}).length, 0);
  const ss = snapshots.reduce((n, s) => n + Object.keys(s.sessionStorage || {}).length, 0);
  return { tabs: snapshots.length, totalCookies, httpOnly, ls, ss };
}

async function runCapture(mode) {
  setStatus("Capturing…");
  try {
    const tabs =
      mode === "active"
        ? await chrome.tabs.query({ active: true, currentWindow: true })
        : await chrome.tabs.query({});
    const results = [];
    for (const t of tabs) {
      const snap = await captureTab(t);
      if (!snap.skipped) results.push(snap);
    }
    lastPayload = mode === "active" ? results[0] || null : results;
    const arr = Array.isArray(lastPayload) ? lastPayload : lastPayload ? [lastPayload] : [];
    const s = summarize(arr);
    summaryEl.hidden = false;
    summaryEl.innerHTML =
      `<b>${s.tabs}</b> tab(s) · <b>${s.totalCookies}</b> cookies ` +
      `(<b>${s.httpOnly}</b> HttpOnly) · <b>${s.ls}</b> localStorage · <b>${s.ss}</b> sessionStorage`;
    outputEl.textContent = JSON.stringify(lastPayload, null, 2);
    setStatus(`Captured ${arr.length} tab(s).`, true);
  } catch (e) {
    setStatus("Capture failed: " + (e?.message || String(e)), false);
  }
}

document.getElementById("active").addEventListener("click", () => runCapture("active"));
document.getElementById("all").addEventListener("click", () => runCapture("all"));

document.getElementById("copy").addEventListener("click", async () => {
  if (!lastPayload) return setStatus("Nothing captured yet.", false);
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastPayload, null, 2));
    setStatus("Copied to clipboard.", true);
  } catch (e) {
    setStatus("Copy failed: " + e.message, false);
  }
});

document.getElementById("download").addEventListener("click", () => {
  if (!lastPayload) return setStatus("Nothing captured yet.", false);
  const blob = new Blob([JSON.stringify(lastPayload, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `nsl-capture-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  setStatus("Downloaded.", true);
});
