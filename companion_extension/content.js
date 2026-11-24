// Stalker Search Companion Content Script
// Open-source, privacy-focused multi-page Google Search crawler.
// Syncs visible public result links across pages via background script to 127.0.0.1:60067,
// notifies on human verification checks, protects tabs from accidental early closure,
// and triggers automatic history removal after sync.
// Zero cookies, credentials, or external telemetry are ever read or transmitted.

(function () {
  const MAX_GOOGLE_PAGES = 10;
  const MAX_NAV_FALLBACK_PAGES = 5;
  const api = typeof browser !== "undefined" ? browser : chrome;

  let isScanning = false;
  let spinnerTimer = null;
  let spinnerStep = 0;
  const SPINNER_FRAMES = ["◐", "◓", "◑", "◒"];

  const BRIDGE_URLS = {
    bridge_ping: "http://127.0.0.1:60067/stalker_ping",
    bridge_status: "http://127.0.0.1:60067/stalker_status",
    bridge_feed: "http://127.0.0.1:60067/stalker_feed",
  };

  async function directBridgeFallback(msg) {
    const url = BRIDGE_URLS[msg.action];
    if (!url) return { ok: false, text: "" };
    try {
      const opts =
        msg.action === "bridge_ping"
          ? { method: "GET" }
          : {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(msg.payload || {}),
            };
      const resp = await fetch(url, opts);
      const text = await resp.text().catch(() => "");
      return { ok: resp.ok, status: resp.status, text };
    } catch (_) {
      return { ok: false, status: 0, text: "" };
    }
  }

  function sendToBackground(msg) {
    return new Promise((resolve) => {
      if (typeof browser !== "undefined" && browser.runtime && typeof browser.runtime.sendMessage === "function") {
        browser.runtime
          .sendMessage(msg)
          .then((reply) => {
            if (reply && typeof reply === "object") {
              resolve(reply);
            } else {
              directBridgeFallback(msg).then(resolve);
            }
          })
          .catch(() => {
            directBridgeFallback(msg).then(resolve);
          });
        return;
      }

      if (typeof chrome !== "undefined" && chrome.runtime && typeof chrome.runtime.sendMessage === "function") {
        try {
          chrome.runtime.sendMessage(msg, (reply) => {
            if (reply && typeof reply === "object") {
              resolve(reply);
            } else {
              directBridgeFallback(msg).then(resolve);
            }
          });
          return;
        } catch (_) {}
      }

      directBridgeFallback(msg).then(resolve);
    });
  }

  function preventEarlyClose(e) {
    if (!isScanning) return undefined;
    e.preventDefault();
    e.returnValue =
      "Stalker Search is still scanning Google pages. Keep this tab open until complete.";
    return e.returnValue;
  }

  function setScanningGuard(active) {
    if (active && !isScanning) {
      isScanning = true;
      window.addEventListener("beforeunload", preventEarlyClose);
    } else if (!active && isScanning) {
      isScanning = false;
      window.removeEventListener("beforeunload", preventEarlyClose);
    }
  }

  function isCaptchaOrVerifyPage(doc) {
    const href = window.location.href.toLowerCase();
    if (href.includes("/sorry/")) return true;
    return Boolean(
      doc.querySelector("#captcha-form, form#captcha-form, iframe[src*='recaptcha']")
    );
  }

  function isExplicitNoResultsPage(doc) {
    const main = doc.querySelector("#search, #rso, #topstuff, #main");
    if (!main) return false;
    const txt = (main.textContent || "").toLowerCase();
    return (
      txt.includes("did not match any documents") ||
      txt.includes("no results found for")
    );
  }

  function postStatus(statusType, message, page, hits) {
    return sendToBackground({
      action: "bridge_status",
      payload: {
        status: statusType,
        message: message || "",
        page: page || 1,
        hits: hits || 0,
      },
    });
  }

  function scrubSearchedUrls(urls, query) {
    sendToBackground({
      action: "clean_history",
      urls: urls || [window.location.href],
      query: query || "",
    });
  }

  function createOrUpdateHud(options) {
    const { tagText, headline, subtext, mode } = options;

    let hud = document.getElementById("stalker-companion-banner");
    if (!hud) {
      hud = document.createElement("aside");
      hud.id = "stalker-companion-banner";
      hud.setAttribute("role", "status");
      hud.setAttribute("aria-live", "polite");
      hud.style.cssText =
        "position:fixed;bottom:24px;right:24px;z-index:2147483647;min-width:410px;max-width:560px;background:#000000;color:#fafafa;padding:20px 24px;border-radius:10px;border:2px solid #ffffff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;box-shadow:0 20px 60px rgba(0,0,0,0.95);line-height:1.45;";

      const topRow = document.createElement("div");
      topRow.style.cssText =
        "display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px;";

      const brandWrap = document.createElement("div");
      brandWrap.style.cssText = "display:flex;align-items:center;gap:8px;";

      const spinEl = document.createElement("span");
      spinEl.id = "stalker-hud-spinner";
      spinEl.style.cssText =
        "font-size:16px;font-weight:700;color:#ffffff;width:18px;display:inline-block;";
      spinEl.textContent = "●";

      const titleEl = document.createElement("span");
      titleEl.style.cssText =
        "font-size:12px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#a3a3a3;";
      titleEl.textContent = "Stalker Search";

      brandWrap.appendChild(spinEl);
      brandWrap.appendChild(titleEl);

      const pillEl = document.createElement("button");
      pillEl.type = "button";
      pillEl.id = "stalker-hud-tag";
      pillEl.style.cssText =
        "font-size:11px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;padding:4px 10px;border-radius:999px;border:1px solid #404040;background:#0a0a0a;color:#fafafa;cursor:pointer;";
      pillEl.addEventListener("click", () => {
        if (!isScanning) {
          sendToBackground({ action: "close_tab" });
          try {
            window.close();
          } catch (_) {}
        }
      });

      topRow.appendChild(brandWrap);
      topRow.appendChild(pillEl);

      const mainEl = document.createElement("div");
      mainEl.id = "stalker-hud-headline";
      mainEl.style.cssText = "font-size:18px;font-weight:700;color:#ffffff;margin-bottom:6px;";

      const subEl = document.createElement("div");
      subEl.id = "stalker-hud-subtext";
      subEl.style.cssText = "font-size:13px;color:#a3a3a3;";

      hud.appendChild(topRow);
      hud.appendChild(mainEl);
      hud.appendChild(subEl);
      document.body.appendChild(hud);
    }

    const spinEl = document.getElementById("stalker-hud-spinner");
    const pillEl = document.getElementById("stalker-hud-tag");
    const mainEl = document.getElementById("stalker-hud-headline");
    const subEl = document.getElementById("stalker-hud-subtext");

    if (mode === "scanning") {
      hud.style.borderColor = "#ffffff";
      pillEl.style.borderColor = "#ffffff";
      pillEl.style.color = "#ffffff";
      pillEl.style.background = "#171717";
      if (!spinnerTimer) {
        spinnerTimer = setInterval(() => {
          const s = document.getElementById("stalker-hud-spinner");
          if (s) {
            spinnerStep = (spinnerStep + 1) % SPINNER_FRAMES.length;
            s.textContent = SPINNER_FRAMES[spinnerStep];
          }
        }, 160);
      }
    } else {
      if (spinnerTimer) {
        clearInterval(spinnerTimer);
        spinnerTimer = null;
      }
      if (mode === "warn") {
        hud.style.borderColor = "#f59e0b";
        pillEl.style.borderColor = "#f59e0b";
        pillEl.style.color = "#fbbf24";
        pillEl.style.background = "#1a1102";
        spinEl.textContent = "!";
        spinEl.style.color = "#fbbf24";
      } else if (mode === "done") {
        hud.style.borderColor = "#22c55e";
        pillEl.style.borderColor = "#22c55e";
        pillEl.style.color = "#4ade80";
        pillEl.style.background = "#05140b";
        spinEl.textContent = "✓";
        spinEl.style.color = "#4ade80";
      } else {
        hud.style.borderColor = "#404040";
        pillEl.style.borderColor = "#404040";
        pillEl.style.color = "#a3a3a3";
        pillEl.style.background = "#0a0a0a";
        spinEl.textContent = "•";
        spinEl.style.color = "#a3a3a3";
      }
    }

    pillEl.textContent = tagText;
    mainEl.textContent = headline;
    subEl.textContent = subtext;
    return hud;
  }

  function queryAllDeep(root, selector) {
    const out = [];
    const stack = [root];
    while (stack.length > 0) {
      const node = stack.pop();
      if (!node || typeof node.querySelectorAll !== "function") continue;
      try {
        const matches = node.querySelectorAll(selector);
        for (const m of matches) out.push(m);
        const allEls = node.querySelectorAll("*");
        for (const el of allEls) {
          if (el.shadowRoot) stack.push(el.shadowRoot);
        }
      } catch (_) {}
    }
    return out;
  }

  function unwrapGoogleUrl(rawHref) {
    if (!rawHref) return "";
    let url = rawHref.trim();
    if (!url || url.startsWith("#") || url.startsWith("javascript:")) return "";
    try {
      const parsed = new URL(url, window.location.origin);
      if (
        parsed.hostname.toLowerCase().includes("google.") &&
        (parsed.pathname === "/url" || parsed.pathname === "/interstitial")
      ) {
        for (const key of ["url", "q", "u", "dest", "target"]) {
          const val = parsed.searchParams.get(key);
          if (val && (val.startsWith("http://") || val.startsWith("https://"))) {
            return val;
          }
        }
      }
      return parsed.toString();
    } catch (_) {
      return "";
    }
  }

  function isInternalGoogleUrl(url) {
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      // Google's signed-out `/goto?url=CAES...` endpoint is an outbound search result link!
      if (
        (host === "google.com" || host.endsWith(".google.com") || host.includes(".google.")) &&
        u.pathname === "/goto" &&
        u.searchParams.has("url")
      ) {
        return false;
      }
      return (
        host === "google.com" ||
        host.endsWith(".google.com") ||
        host.includes(".google.") ||
        host.endsWith("gstatic.com") ||
        host.endsWith("googleusercontent.com") ||
        host.endsWith("googleapis.com") ||
        host === "accounts.youtube.com"
      );
    } catch (_) {
      return true;
    }
  }

  function isChromeExcluded(el) {
    if (!el || typeof el.closest !== "function") return false;
    return Boolean(
      el.closest("#gb, #fbar, #swml, #top_nav, #hdtb, footer, aside#stalker-companion-banner")
    );
  }

  function findResultCard(el) {
    const knownCard =
      el.closest("div[data-snc]") ||
      el.closest("div.MjjYud") ||
      el.closest("div.Ww4FFb") ||
      el.closest("div.srKDX") ||
      el.closest("div.g") ||
      el.closest("div.N54PNb") ||
      el.closest("div.tF2Cxc");
    if (knownCard) return knownCard;

    // Fallback: walk up above any <a> wrapper until we reach the outer container for this single result (1 <h3>)
    let cur = el.closest("a") || el;
    let best = cur.parentElement;
    while (cur && cur.parentElement && cur.parentElement !== document.body) {
      const parent = cur.parentElement;
      if (
        parent.id === "rso" ||
        parent.id === "search" ||
        parent.id === "main" ||
        parent.id === "center_col"
      ) {
        break;
      }
      const h3Count = parent.querySelectorAll("h3").length;
      if (h3Count > 1) break;
      best = parent;
      cur = parent;
    }
    return best || el.parentElement;
  }

  function extractSnippetForElement(el, title) {
    const card = findResultCard(el);
    if (!card || card === document.body) return "";

    let citePrefix = "";
    try {
      const citeEl = card.querySelector("cite");
      const siteEl = card.querySelector(".VuuXrf");
      const rawCite = citeEl ? (citeEl.innerText || citeEl.textContent || "").trim() : "";
      const rawSite = siteEl ? (siteEl.innerText || siteEl.textContent || "").trim() : "";

      const parts = [];
      if (rawCite) {
        const firstPart = rawCite.split(/\s*[›·]\s*/)[0].trim();
        if (firstPart) parts.push(firstPart);
      }
      if (rawSite && !parts.includes(rawSite)) {
        parts.push(rawSite);
      }
      if (parts.length > 0) {
        citePrefix = `[Source: ${parts.join(" | ")}] `;
      }
    } catch (_) {}

    const bodySnippet = (card.innerText || card.textContent || "")
      .replace(title, "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 420);

    return `${citePrefix}${bodySnippet}`.trim();
  }

  function extractResultsFromDoc(doc, seenUrls) {
    const pageResults = [];
    const root = doc.querySelector("#rso, #search, #main") || doc;

    // Pass 1: Match headings across all Google SERP DOM layouts (piercing open Shadow DOM too)
    const headings = queryAllDeep(root, "h3, [role='heading']");
    for (const heading of headings) {
      if (isChromeExcluded(heading)) continue;

      const anchor =
        heading.closest("a[href]") ||
        heading.querySelector("a[href]") ||
        (heading.parentElement && heading.parentElement.querySelector("a[href]"));
      if (!anchor) continue;

      const rawHref =
        anchor.getAttribute("href") ||
        anchor.href ||
        anchor.getAttribute("data-href") ||
        anchor.getAttribute("data-url") ||
        "";
      const url = unwrapGoogleUrl(rawHref);
      if (!url.startsWith("http") || isInternalGoogleUrl(url)) continue;
      if (seenUrls.has(url)) continue;

      const title = (heading.innerText || heading.textContent || "").trim();
      if (title.length < 2) continue;

      seenUrls.add(url);
      const snippet = extractSnippetForElement(heading, title);
      pageResults.push({ title, url, snippet });
    }

    // Pass 2: Full-document fallback (handles AI Mode citation cards & empty aria-label overlay <a> tags)
    if (pageResults.length === 0) {
      const anchors = queryAllDeep(doc, "a[href], a[data-href], a[data-url]");
      for (const anchor of anchors) {
        if (isChromeExcluded(anchor)) continue;
        const rawHref =
          anchor.getAttribute("href") ||
          anchor.href ||
          anchor.getAttribute("data-href") ||
          anchor.getAttribute("data-url") ||
          "";
        const url = unwrapGoogleUrl(rawHref);
        if (!url.startsWith("http") || isInternalGoogleUrl(url)) continue;
        if (seenUrls.has(url)) continue;

        const card =
          anchor.closest("div[data-snc], div.MjjYud, div.g, div.N54PNb, li") ||
          anchor.parentElement;
        const headingText = card
          ? ((card.querySelector("h3, h2, [role='heading']") || {}).innerText || "").trim()
          : "";
        const rawTitle =
          (anchor.getAttribute("aria-label") || "").trim() ||
          (anchor.getAttribute("title") || "").trim() ||
          headingText ||
          (anchor.innerText || anchor.textContent || "").replace(/\s+/g, " ").trim() ||
          url;

        seenUrls.add(url);
        const snippet = extractSnippetForElement(anchor, rawTitle);
        pageResults.push({ title: rawTitle.slice(0, 180), url, snippet });
      }
    }

    return pageResults;
  }

  function buildDiagnostics(doc) {
    try {
      const allAnchors = queryAllDeep(doc, "a[href]");
      let extCount = 0;
      for (const a of allAnchors) {
        const u = unwrapGoogleUrl(a.getAttribute("href") || a.href || "");
        if (u.startsWith("http") && !isInternalGoogleUrl(u)) extCount++;
      }
      const h3Count = queryAllDeep(doc, "h3").length;
      const udm = new URLSearchParams(window.location.search).get("udm") || "none";
      const path = window.location.pathname;
      return `a=${allAnchors.length} ext=${extCount} h3=${h3Count} udm=${udm} path=${path}`;
    } catch (_) {
      return "diag_err";
    }
  }

  function findNextPageUrl(doc, currentPageNum, lastPageHitCount) {
    const nextBtn =
      doc.querySelector("a#pnnext") ||
      doc.querySelector('a[aria-label="Next page"]') ||
      doc.querySelector('a[aria-label="Next"]') ||
      doc.querySelector('td.d6cvqb a[href*="start="]');
    if (nextBtn) {
      const href = nextBtn.getAttribute("href");
      if (href) {
        try {
          const u = new URL(href, window.location.origin);
          if (!u.searchParams.has("udm")) u.searchParams.set("udm", "14");
          return u.toString();
        } catch (_) {}
      }
    }

    const expectedStart = String(currentPageNum * 10);
    const navLinks = doc.querySelectorAll(
      'div[role="navigation"] a[href*="start="], table.AaVjTc a[href*="start="], #botstuff a[href*="start="]'
    );
    for (const link of navLinks) {
      const href = link.getAttribute("href");
      if (!href) continue;
      try {
        const u = new URL(href, window.location.origin);
        if (u.searchParams.get("start") === expectedStart) {
          if (!u.searchParams.has("udm")) u.searchParams.set("udm", "14");
          return u.toString();
        }
      } catch (_) {}
    }

    if (lastPageHitCount >= 6) {
      try {
        const nextU = new URL(window.location.href);
        nextU.searchParams.set("udm", "14");
        nextU.searchParams.set("start", expectedStart);
        return nextU.toString();
      } catch (_) {}
    }

    return null;
  }

  async function waitForPageResults(seenUrls) {
    let hits = extractResultsFromDoc(document, seenUrls);
    if (hits.length > 0 || isExplicitNoResultsPage(document)) {
      return hits;
    }

    createOrUpdateHud({
      tagText: "DO NOT CLOSE TAB",
      headline: "Waiting for Google Results to Render...",
      subtext: "Waiting for Google page hydration before extracting results. Keep this tab open.",
      mode: "scanning",
    });

    // Poll up to 4.5 seconds (at fast 250ms intervals) for lazy-hydrated / streaming Google SERPs
    for (let attempt = 0; attempt < 18; attempt++) {
      await new Promise((r) => setTimeout(r, 250));
      if (isCaptchaOrVerifyPage(document) || isExplicitNoResultsPage(document)) {
        break;
      }
      hits = extractResultsFromDoc(document, seenUrls);
      if (hits.length > 0) {
        return hits;
      }
    }

    return hits;
  }

  async function crawlFromCurrentTab(startPageNum) {
    const seenUrls = new Set();
    const visitedUrls = [window.location.href];
    const allResults = [];
    let currentDoc = document;
    let pageNum = startPageNum;

    setScanningGuard(true);

    let firstHits = await waitForPageResults(seenUrls);

    // If page still has 0 results and isn't explicitly udm=14 yet, try navigating once to classic Web tab
    if (firstHits.length === 0 && !isExplicitNoResultsPage(document)) {
      try {
        const u = new URL(window.location.href);
        if (u.searchParams.get("udm") !== "14") {
          u.searchParams.set("udm", "14");
          setScanningGuard(false);
          window.location.replace(u.toString());
          return { navigated: true };
        }
      } catch (_) {}
    }

    allResults.push(...firstHits);

    let nextUrl = findNextPageUrl(currentDoc, pageNum, firstHits.length);

    if (allResults.length === 0 && !nextUrl) {
      return {
        navigated: false,
        allResults,
        pagesScanned: 1,
        visitedUrls,
        interruptedByCaptcha: false,
        needsRealNavTo: null,
      };
    }

    createOrUpdateHud({
      tagText: "DO NOT CLOSE TAB",
      headline: nextUrl
        ? `Loading Page ${pageNum + 1} of Google Results... (${allResults.length} on Page ${pageNum})`
        : `Processing ${allResults.length} Google Results...`,
      subtext:
        "Keep this tab open until syncing finishes. Searched URLs will be cleared from history automatically.",
      mode: "scanning",
    });
    await postStatus(
      "crawling",
      `Scanning Google Page ${pageNum} (${allResults.length} results)`,
      pageNum,
      allResults.length
    );

    let interruptedByCaptcha = false;
    let needsRealNavTo = null;
    let pagesScannedHere = 1;

    while (nextUrl && pageNum < MAX_GOOGLE_PAGES) {
      const candidateNextUrl = nextUrl;
      const candidatePage = pageNum + 1;

      createOrUpdateHud({
        tagText: "DO NOT CLOSE TAB",
        headline: `Loading Page ${candidatePage} of Results... (${allResults.length} collected)`,
        subtext: "Crawling additional Google pages. Do not close this tab yet.",
        mode: "scanning",
      });
      await postStatus(
        "crawling",
        `Scanning Google Page ${candidatePage} (${allResults.length} results so far)`,
        candidatePage,
        allResults.length
      );

      await new Promise((r) => setTimeout(r, 550));

      try {
        const resp = await fetch(candidateNextUrl, { credentials: "same-origin" });
        if (!resp.ok) {
          if (resp.status === 429) interruptedByCaptcha = true;
          break;
        }
        const html = await resp.text();
        const parser = new DOMParser();
        const nextDoc = parser.parseFromString(html, "text/html");
        if (isCaptchaOrVerifyPage(nextDoc)) {
          interruptedByCaptcha = true;
          break;
        }
        const hits = extractResultsFromDoc(nextDoc, seenUrls);
        if (hits.length === 0) {
          // If Google served a JS-required empty shell to background fetch() on fresh Firefox,
          // fall back to real browser-tab navigation so Firefox executes Google's JS for Page 2..5!
          if (!isExplicitNoResultsPage(nextDoc) && candidatePage <= MAX_NAV_FALLBACK_PAGES) {
            needsRealNavTo = candidateNextUrl;
          }
          break;
        }
        pageNum = candidatePage;
        pagesScannedHere++;
        visitedUrls.push(candidateNextUrl);
        currentDoc = nextDoc;
        allResults.push(...hits);
        nextUrl = findNextPageUrl(currentDoc, pageNum, hits.length);
      } catch (_) {
        break;
      }
    }

    return {
      navigated: false,
      allResults,
      pagesScanned: pagesScannedHere,
      visitedUrls,
      interruptedByCaptcha,
      needsRealNavTo,
    };
  }

  // When loaded on the local Stalker Search Web UI (127.0.0.1:7878), sync extension & Private Window status
  if (window.location.hostname === "127.0.0.1") {
    function syncDashboardStatus() {
      sendToBackground({ action: "check_incognito_access" }).then((reply) => {
        document.documentElement.dataset.stalkerCompanion = "active";
        document.documentElement.dataset.stalkerIncognitoAllowed =
          reply && reply.incognitoAllowed ? "true" : "false";
      });
    }
    syncDashboardStatus();
    setInterval(syncDashboardStatus, 1200);
    return;
  }

  sendToBackground({ action: "bridge_ping" }).then(async (pingReply) => {
    if (!pingReply || !pingReply.ok || (pingReply.text || "").trim() !== "stalker_pong") {
      return;
    }

    const params = new URLSearchParams(window.location.search);
    const query = params.get("q") || "";
    const startOffset = parseInt(params.get("start") || "0", 10) || 0;
    const startPageNum = Math.floor(startOffset / 10) + 1;

    if (isCaptchaOrVerifyPage(document)) {
      // Do NOT attach beforeunload on /sorry/ so Google can freely redirect back to /search once verified
      setScanningGuard(false);
      createOrUpdateHud({
        tagText: "HUMAN VERIFICATION NEEDED",
        headline: "Please Verify You Are Human in This Tab",
        subtext:
          "Google requested human verification in this window. Complete the check here (do NOT close this tab), or switch to 'Open Google Search (Faster)' mode.",
        mode: "warn",
      });
      const notifyVerify = () =>
        postStatus(
          "human_verify_needed",
          "Google requires human verification in the opened browser tab. Complete it there to continue.",
          startPageNum,
          0
        );
      await notifyVerify();
      setInterval(notifyVerify, 5000);
      return;
    }

    const res = await crawlFromCurrentTab(startPageNum);
    if (res.navigated) {
      return;
    }

    const { allResults, pagesScanned, visitedUrls, interruptedByCaptcha, needsRealNavTo } = res;

    if (interruptedByCaptcha) {
      await postStatus(
        "human_verify_needed",
        "Google paused pagination for verification after collecting initial results.",
        startPageNum + pagesScanned - 1,
        allResults.length
      );
    }

    // If background fetch() was JS-gated by Google, stream current page (`done: false`)
    // and navigate this tab directly to Page N+1!
    if (needsRealNavTo) {
      await sendToBackground({
        action: "bridge_feed",
        payload: { query, results: allResults, done: false },
      });
      scrubSearchedUrls(visitedUrls, query);
      setScanningGuard(false);
      window.location.href = needsRealNavTo;
      return;
    }

    const diag = allResults.length === 0 ? buildDiagnostics(document) : "";
    const feedReply = await sendToBackground({
      action: "bridge_feed",
      payload: { query, results: allResults, done: true, diag },
    });

    setScanningGuard(false);
    scrubSearchedUrls(visitedUrls, query);

    if (feedReply && feedReply.ok) {
      const isPrivate = api && api.extension && api.extension.inIncognitoContext;
      const historyNote = isPrivate
        ? "Private window used (zero history saved). Auto-closing this tab now..."
        : "Search URL removed from browser history. Auto-closing this tab now...";

      const totalPages = startPageNum + pagesScanned - 1;

      if (allResults.length > 0) {
        createOrUpdateHud({
          tagText: "CLOSE TAB NOW ✕",
          headline: `Done! Synced ${allResults.length} Results (Up to Page ${totalPages})`,
          subtext: historyNote,
          mode: "done",
        });
      } else {
        createOrUpdateHud({
          tagText: "CLOSE TAB NOW ✕",
          headline: "Scan Complete · 0 Results Found for This Query",
          subtext: `${historyNote} [${diag}]`,
          mode: "idle",
        });
      }

      setTimeout(() => {
        sendToBackground({ action: "close_tab" });
        try {
          window.close();
        } catch (_) {}
      }, 650);
    }
  });
})();
