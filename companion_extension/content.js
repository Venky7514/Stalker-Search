// Stalker Search Companion Content Script
// Open-source, privacy-focused multi-page Google Search crawler.
// Syncs visible public result links across pages via background script to 127.0.0.1:60067,
// notifies on human verification checks, protects tabs from accidental early closure,
// and triggers automatic history removal after sync.
// Zero cookies, credentials, or external telemetry are ever read or transmitted.

(function () {
  const MAX_GOOGLE_PAGES = 10;
  const api = typeof browser !== "undefined" ? browser : chrome;

  let isScanning = false;
  let spinnerTimer = null;
  let spinnerStep = 0;
  const SPINNER_FRAMES = ["◐", "◓", "◑", "◒"];

  function sendToBackground(msg) {
    return new Promise((resolve) => {
      if (!api || !api.runtime || typeof api.runtime.sendMessage !== "function") {
        resolve({ ok: false, text: "" });
        return;
      }
      try {
        const res = api.runtime.sendMessage(msg, (reply) => {
          resolve(reply || { ok: false, text: "" });
        });
        if (res && typeof res.then === "function") {
          res
            .then((reply) => resolve(reply || { ok: false, text: "" }))
            .catch(() => resolve({ ok: false, text: "" }));
        }
      } catch (_) {
        resolve({ ok: false, text: "" });
      }
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

      const pillEl = document.createElement("span");
      pillEl.id = "stalker-hud-tag";
      pillEl.style.cssText =
        "font-size:11px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;padding:3px 9px;border-radius:999px;border:1px solid #404040;background:#0a0a0a;color:#fafafa;";

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
        const target =
          parsed.searchParams.get("q") ||
          parsed.searchParams.get("url") ||
          parsed.searchParams.get("u");
        if (target && target.startsWith("http")) {
          return target;
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
      return (
        host === "google.com" ||
        host.endsWith(".google.com") ||
        host.includes(".google.") ||
        host.endsWith("gstatic.com") ||
        host.endsWith("googleusercontent.com") ||
        host.endsWith("googleapis.com") ||
        host.endsWith("youtube.com/redirect")
      );
    } catch (_) {
      return true;
    }
  }

  function extractSnippetForElement(el, title) {
    const card =
      el.closest("div[data-snc]") ||
      el.closest("div.MjjYud") ||
      el.closest("div.g") ||
      el.closest("div.N54PNb") ||
      el.closest("div.tF2Cxc");
    if (!card) return "";
    return (card.innerText || card.textContent || "")
      .replace(title, "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 450);
  }

  function extractResultsFromDoc(doc, seenUrls) {
    const pageResults = [];
    const root = doc.querySelector("#rso, #search, #main") || doc;

    // Pass 1: Match headings across all Google SERP DOM layouts
    // (<a><h3>...</h3></a>, <h3><a>...</a></h3>, or sibling <a> + <h3>)
    const headings = root.querySelectorAll("h3, [role='heading']");
    for (const heading of headings) {
      if (heading.closest("header, footer, nav, #fbar, #swml, #gb, [role='navigation']")) {
        continue;
      }

      const anchor =
        heading.closest("a[href]") ||
        heading.querySelector("a[href]") ||
        (heading.parentElement && heading.parentElement.querySelector("a[href]"));
      if (!anchor) continue;

      const rawHref = anchor.getAttribute("href") || anchor.href || "";
      const url = unwrapGoogleUrl(rawHref);
      if (!url.startsWith("http") || isInternalGoogleUrl(url)) continue;
      if (seenUrls.has(url)) continue;

      const title = (heading.innerText || heading.textContent || "").trim();
      if (title.length < 2) continue;

      seenUrls.add(url);
      const snippet = extractSnippetForElement(heading, title);
      pageResults.push({ title, url, snippet });
    }

    // Pass 2: Fallback across full document (handles AI Mode citation sidebars & alternative SERP layouts)
    if (pageResults.length === 0) {
      const anchors = doc.querySelectorAll("a[href]");
      for (const anchor of anchors) {
        if (anchor.closest("header, footer, nav, #fbar, #swml, #gb, [role='navigation'], aside#stalker-companion-banner")) {
          continue;
        }
        const rawHref = anchor.getAttribute("href") || anchor.href || "";
        const url = unwrapGoogleUrl(rawHref);
        if (!url.startsWith("http") || isInternalGoogleUrl(url)) continue;
        if (seenUrls.has(url)) continue;

        const title = (anchor.innerText || anchor.textContent || "").replace(/\s+/g, " ").trim();
        if (title.length < 4) continue;

        seenUrls.add(url);
        const snippet = extractSnippetForElement(anchor, title);
        pageResults.push({ title: title.slice(0, 180), url, snippet });
      }
    }

    return pageResults;
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
          return new URL(href, window.location.origin).toString();
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
          return u.toString();
        }
      } catch (_) {}
    }

    // Fallback for continuous-scroll / hidden-pagination Google layouts:
    // If the current page had a healthy batch of results (>= 6), construct the next &start= URL directly.
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

  async function crawlAllGooglePages() {
    const seenUrls = new Set();
    const visitedUrls = [window.location.href];
    const allResults = [];
    let currentDoc = document;
    let pageNum = 1;

    setScanningGuard(true);

    let page1Hits = extractResultsFromDoc(currentDoc, seenUrls);
    // If Google is still hydrating DOM right after document_idle, wait briefly and retry once
    if (page1Hits.length === 0) {
      await new Promise((r) => setTimeout(r, 900));
      page1Hits = extractResultsFromDoc(currentDoc, seenUrls);
    }
    allResults.push(...page1Hits);

    let nextUrl = findNextPageUrl(currentDoc, pageNum, page1Hits.length);

    if (allResults.length === 0 && !nextUrl) {
      return { allResults, pagesScanned: 1, visitedUrls, interruptedByCaptcha: false };
    }

    createOrUpdateHud({
      tagText: "DO NOT CLOSE TAB",
      headline: nextUrl
        ? `Loading Page 2 of Google Results... (${allResults.length} results on Page 1)`
        : `Processing ${allResults.length} Google Results...`,
      subtext:
        "Keep this tab open until syncing finishes. Searched URLs will be cleared from history automatically.",
      mode: "scanning",
    });
    await postStatus(
      "crawling",
      `Loading Google Page 1 (${allResults.length} results)`,
      1,
      allResults.length
    );

    let interruptedByCaptcha = false;

    while (nextUrl && pageNum < MAX_GOOGLE_PAGES) {
      pageNum++;
      visitedUrls.push(nextUrl);

      createOrUpdateHud({
        tagText: "DO NOT CLOSE TAB",
        headline: `Loading Page ${pageNum} of Results... (${allResults.length} collected)`,
        subtext: "Crawling additional Google pages in the background. Do not close this tab yet.",
        mode: "scanning",
      });
      await postStatus(
        "crawling",
        `Scanning Google Page ${pageNum} (${allResults.length} results so far)`,
        pageNum,
        allResults.length
      );

      await new Promise((r) => setTimeout(r, 900));

      try {
        const resp = await fetch(nextUrl, { credentials: "same-origin" });
        if (!resp.ok) {
          if (resp.status === 429) interruptedByCaptcha = true;
          break;
        }
        const html = await resp.text();
        const parser = new DOMParser();
        currentDoc = parser.parseFromString(html, "text/html");
        if (isCaptchaOrVerifyPage(currentDoc)) {
          interruptedByCaptcha = true;
          break;
        }
        const hits = extractResultsFromDoc(currentDoc, seenUrls);
        if (hits.length === 0) break;
        allResults.push(...hits);
        nextUrl = findNextPageUrl(currentDoc, pageNum, hits.length);
      } catch (_) {
        break;
      }
    }

    return { allResults, pagesScanned: pageNum, visitedUrls, interruptedByCaptcha };
  }

  sendToBackground({ action: "bridge_ping" }).then(async (pingReply) => {
    if (!pingReply || !pingReply.ok || (pingReply.text || "").trim() !== "stalker_pong") {
      return;
    }

    const params = new URLSearchParams(window.location.search);
    const query = params.get("q") || "";

    if (isCaptchaOrVerifyPage(document)) {
      setScanningGuard(true);
      createOrUpdateHud({
        tagText: "HUMAN VERIFICATION NEEDED",
        headline: "Please Verify You Are Human in This Tab",
        subtext:
          "Google blocked automated pagination in this window. Complete the verification check here (do NOT close this tab), or switch to 'Open Google Search (Faster)' mode.",
        mode: "warn",
      });
      await postStatus(
        "human_verify_needed",
        "Google requires human verification in the opened browser tab. Complete it there to continue.",
        1,
        0
      );
      return;
    }

    const { allResults, pagesScanned, visitedUrls, interruptedByCaptcha } =
      await crawlAllGooglePages();

    if (interruptedByCaptcha) {
      await postStatus(
        "human_verify_needed",
        "Google paused pagination for verification after collecting initial results.",
        pagesScanned,
        allResults.length
      );
    }

    const feedReply = await sendToBackground({
      action: "bridge_feed",
      payload: { query, results: allResults },
    });

    setScanningGuard(false);
    scrubSearchedUrls(visitedUrls, query);

    if (feedReply && feedReply.ok) {
      const isPrivate = api && api.extension && api.extension.inIncognitoContext;
      const historyNote = isPrivate
        ? "Private window used (zero history saved). Safe to close this tab now."
        : "Search URL removed from browser history. Safe to close this tab now.";

      if (allResults.length > 0) {
        createOrUpdateHud({
          tagText: "SAFE TO CLOSE TAB",
          headline: `Done! Synced ${allResults.length} Results Across ${pagesScanned} Page${pagesScanned > 1 ? "s" : ""}`,
          subtext: historyNote,
          mode: "done",
        });
      } else {
        createOrUpdateHud({
          tagText: "SAFE TO CLOSE TAB",
          headline: "Scan Complete · 0 Results Found for This Query",
          subtext: historyNote,
          mode: "idle",
        });
      }
    }
  });
})();
