// Stalker Search Companion Content Script
// Open-source, privacy-focused multi-page Google Search crawler.
// Syncs visible public result links across pages directly to 127.0.0.1:60067,
// notifies on human verification checks, protects tabs from accidental early closure,
// and triggers automatic history removal after sync.
// Zero cookies, credentials, or external telemetry are ever read or transmitted.

(function () {
  const BRIDGE_PING = "http://127.0.0.1:60067/stalker_ping";
  const BRIDGE_FEED = "http://127.0.0.1:60067/stalker_feed";
  const BRIDGE_STATUS = "http://127.0.0.1:60067/stalker_status";
  const MAX_GOOGLE_PAGES = 10;
  const api = typeof browser !== "undefined" ? browser : chrome;

  let isScanning = false;
  let spinnerTimer = null;
  let spinnerStep = 0;
  const SPINNER_FRAMES = ["◐", "◓", "◑", "◒"];

  function preventEarlyClose(e) {
    if (!isScanning) return undefined;
    e.preventDefault();
    e.returnValue = "Stalker Search is still scanning Google pages. Keep this tab open until complete.";
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
    return fetch(BRIDGE_STATUS, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: statusType,
        message: message || "",
        page: page || 1,
        hits: hits || 0,
      }),
    }).catch(() => {});
  }

  function scrubSearchedUrls(urls, query) {
    try {
      if (api && api.runtime && typeof api.runtime.sendMessage === "function") {
        api.runtime.sendMessage({
          action: "clean_history",
          urls: urls || [window.location.href],
          query: query || "",
        });
      }
    } catch (_) {}
  }

  function createOrUpdateHud(options) {
    const {
      tagText,
      headline,
      subtext,
      mode, // "scanning" | "warn" | "done" | "idle"
    } = options;

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
      spinEl.style.cssText = "font-size:16px;font-weight:700;color:#ffffff;width:18px;display:inline-block;";
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

  function extractResultsFromDoc(doc, seenUrls) {
    const pageResults = [];
    const headings = doc.querySelectorAll("a h3");

    for (const h3 of headings) {
      const anchor = h3.closest("a");
      if (!anchor) continue;
      const rawHref = anchor.getAttribute("href") || anchor.href || "";
      let url = rawHref;
      if (url.startsWith("/url?")) {
        try {
          const parsed = new URL(url, window.location.origin);
          url = parsed.searchParams.get("q") || parsed.searchParams.get("url") || url;
        } catch (_) {}
      }
      if (!url.startsWith("http") || url.includes("google.com/")) continue;
      if (seenUrls.has(url)) continue;
      seenUrls.add(url);

      const title = (h3.innerText || h3.textContent || "").trim();
      if (!title) continue;

      const card =
        h3.closest("div[data-snc]") ||
        h3.closest("div.MjjYud") ||
        h3.closest("div.g");

      let snippet = "";
      if (card) {
        snippet = (card.innerText || card.textContent || "")
          .replace(title, "")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 450);
      }

      pageResults.push({ title, url, snippet });
    }
    return pageResults;
  }

  function findNextPageUrl(doc) {
    const nextBtn =
      doc.querySelector("a#pnnext") ||
      doc.querySelector('a[aria-label="Next page"]') ||
      doc.querySelector('a[aria-label="Next"]');
    if (!nextBtn) return null;
    const href = nextBtn.getAttribute("href");
    if (!href) return null;
    try {
      return new URL(href, window.location.origin).toString();
    } catch (_) {
      return null;
    }
  }

  async function crawlAllGooglePages(query) {
    const seenUrls = new Set();
    const visitedUrls = [window.location.href];
    const allResults = [];
    let currentDoc = document;
    let pageNum = 1;

    setScanningGuard(true);

    const page1Hits = extractResultsFromDoc(currentDoc, seenUrls);
    allResults.push(...page1Hits);

    let nextUrl = findNextPageUrl(currentDoc);

    if (allResults.length === 0 && !nextUrl) {
      return { allResults, pagesScanned: 1, visitedUrls, interruptedByCaptcha: false };
    }

    createOrUpdateHud({
      tagText: "DO NOT CLOSE TAB",
      headline: nextUrl
        ? `Loading Page 2 of Google Results... (${allResults.length} results on Page 1)`
        : `Processing ${allResults.length} Google Results...`,
      subtext: "Keep this tab open until syncing finishes. Searched URLs will be cleared from history automatically.",
      mode: "scanning",
    });
    await postStatus("crawling", `Loading Google Page 1 (${allResults.length} results)`, 1, allResults.length);

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
        nextUrl = findNextPageUrl(currentDoc);
      } catch (_) {
        break;
      }
    }

    return { allResults, pagesScanned: pageNum, visitedUrls, interruptedByCaptcha };
  }

  // Check if local Stalker Search listener is active on 127.0.0.1:60067
  fetch(BRIDGE_PING)
    .then((r) => r.text())
    .then(async (txt) => {
      if (txt.trim() !== "stalker_pong") return;

      const params = new URLSearchParams(window.location.search);
      const query = params.get("q") || "";

      // If Google is currently prompting for Human Verification in this tab (e.g. Incognito),
      // alert the user loudly in both this tab and the local Web UI and wait without touching the challenge.
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
        await crawlAllGooglePages(query);

      if (interruptedByCaptcha) {
        await postStatus(
          "human_verify_needed",
          "Google paused pagination for verification after collecting initial results.",
          pagesScanned,
          allResults.length
        );
      }

      fetch(BRIDGE_FEED, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, results: allResults }),
      })
        .then((r) => {
          setScanningGuard(false);
          scrubSearchedUrls(visitedUrls, query);

          if (r.ok) {
            const isPrivate =
              api &&
              api.extension &&
              api.extension.inIncognitoContext;

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
          } else {
            setScanningGuard(false);
          }
        })
        .catch(() => {
          setScanningGuard(false);
        });
    })
    .catch(() => {
      // Local scanner not listening right now
    });
})();
