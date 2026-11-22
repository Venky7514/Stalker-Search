// Stalker Search Companion Background Script
// Removes scanned Google Search URLs from the browser's local history after sync
// so even standard-window searches leave zero search history on the device.

(function () {
  const api = typeof browser !== "undefined" ? browser : chrome;

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

  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.action === "clean_history") {
      // Incognito tabs do not write to disk history
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

      // Also remove any redirected Google search history entries for this query from the last 10 minutes
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
