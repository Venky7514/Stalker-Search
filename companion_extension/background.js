// Stalker Search Companion Background Script
// 1. Proxies localhost 127.0.0.1:60067 requests cleanly from extension origin
//    so HTTPS-Only Mode or page CSP on Google never blocks local companion sync.
// 2. Removes scanned Google Search URLs from local browser history after sync
//    so even standard-window searches leave zero search history on the device.

(function () {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const BRIDGE_PING = "http://127.0.0.1:60067/stalker_ping";
  const BRIDGE_FEED = "http://127.0.0.1:60067/stalker_feed";
  const BRIDGE_STATUS = "http://127.0.0.1:60067/stalker_status";

  if (!api || !api.runtime || !api.runtime.onMessage) {
    return;
  }

  function safeDeleteUrl(url) {
    if (!api.history || typeof api.history.deleteUrl !== "function") return;
    if (typeof url === "string" && url.startsWith("http")) {
      try {
        const res = api.history.deleteUrl({ url });
        if (res && typeof res.catch === "function") {
          res.catch(() => {});
        }
      } catch (_) {}
    }
  }

  function sendBridgeRequest(url, options, sendResponse) {
    fetch(url, options)
      .then(async (resp) => {
        const text = await resp.text().catch(() => "");
        sendResponse({ ok: resp.ok, status: resp.status, text });
      })
      .catch(() => {
        sendResponse({ ok: false, status: 0, text: "" });
      });
    return true;
  }

  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || typeof message.action !== "string") {
      return false;
    }

    if (message.action === "bridge_ping") {
      return sendBridgeRequest(BRIDGE_PING, { method: "GET" }, sendResponse);
    }

    if (message.action === "bridge_status") {
      return sendBridgeRequest(
        BRIDGE_STATUS,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(message.payload || {}),
        },
        sendResponse
      );
    }

    if (message.action === "bridge_feed") {
      return sendBridgeRequest(
        BRIDGE_FEED,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(message.payload || {}),
        },
        sendResponse
      );
    }

    if (message.action === "clean_history") {
      if (sender && sender.tab && sender.tab.incognito) {
        if (typeof sendResponse === "function") {
          sendResponse({ cleaned: true, incognito: true });
        }
        return false;
      }

      if (Array.isArray(message.urls)) {
        for (const rawUrl of message.urls) {
          safeDeleteUrl(rawUrl);
        }
      }

      if (api.history && typeof api.history.search === "function") {
        const queryText = typeof message.query === "string" ? message.query.trim() : "";
        const since = Date.now() - 10 * 60 * 1000;
        const onSearchResults = (items) => {
          if (!Array.isArray(items)) return;
          for (const item of items) {
            if (!item || !item.url || !item.url.includes("google.")) continue;
            if (!queryText) {
              safeDeleteUrl(item.url);
              continue;
            }
            try {
              const u = new URL(item.url);
              const q = (u.searchParams.get("q") || "").trim();
              if (q && q.toLowerCase() === queryText.toLowerCase()) {
                safeDeleteUrl(item.url);
              }
            } catch (_) {
              safeDeleteUrl(item.url);
            }
          }
        };

        try {
          const maybePromise = api.history.search({
            text: queryText || "google.com/search",
            startTime: since,
            maxResults: 50,
          });
          if (maybePromise && typeof maybePromise.then === "function") {
            maybePromise
              .then((items) => {
                onSearchResults(items);
                if (typeof sendResponse === "function") {
                  sendResponse({ cleaned: true });
                }
              })
              .catch(() => {
                if (typeof sendResponse === "function") {
                  sendResponse({ cleaned: false });
                }
              });
            return true;
          } else {
            api.history.search(
              { text: queryText || "google.com/search", startTime: since, maxResults: 50 },
              (items) => {
                onSearchResults(items);
                if (typeof sendResponse === "function") {
                  sendResponse({ cleaned: true });
                }
              }
            );
            return true;
          }
        } catch (_) {}
      }

      if (typeof sendResponse === "function") {
        sendResponse({ cleaned: true });
      }
    }
    return false;
  });
})();
