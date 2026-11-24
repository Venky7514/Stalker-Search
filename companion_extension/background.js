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
  const UI_HEARTBEAT = "http://127.0.0.1:7878/api/companion_heartbeat";

  if (!api || !api.runtime || !api.runtime.onMessage) {
    return;
  }

  function queryIncognitoAllowed() {
    return new Promise((resolve) => {
      if (api.extension && typeof api.extension.isAllowedIncognitoAccess === "function") {
        try {
          if (typeof browser !== "undefined") {
            browser.extension
              .isAllowedIncognitoAccess()
              .then((allowed) => resolve(Boolean(allowed)))
              .catch(() => resolve(false));
            return;
          }
          api.extension.isAllowedIncognitoAccess((allowed) => resolve(Boolean(allowed)));
          return;
        } catch (_) {}
      }
      resolve(false);
    });
  }

  // Push live Firefox Companion & Private Window permission state to the local Stalker Search desktop app
  async function reportCompanionHeartbeat() {
    try {
      const incognitoAllowed = await queryIncognitoAllowed();
      await fetch(UI_HEARTBEAT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          installed: true,
          incognito_allowed: incognitoAllowed,
        }),
      });
    } catch (_) {}
  }
  reportCompanionHeartbeat();
  setInterval(reportCompanionHeartbeat, 2000);

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
    const promise = fetch(url, options)
      .then(async (resp) => {
        const text = await resp.text().catch(() => "");
        return { ok: resp.ok, status: resp.status, text };
      })
      .catch(() => ({ ok: false, status: 0, text: "" }));

    if (typeof browser !== "undefined") {
      return promise;
    }
    promise.then((res) => sendResponse(res));
    return true;
  }

  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || typeof message.action !== "string") {
      return false;
    }

    if (message.action === "check_incognito_access") {
      return queryIncognitoAllowed().then((allowed) => ({
        installed: true,
        incognitoAllowed: allowed,
      }));
    }

    if (message.action === "close_tab") {
      if (
        sender &&
        sender.tab &&
        typeof sender.tab.id === "number" &&
        api.tabs &&
        typeof api.tabs.remove === "function"
      ) {
        try {
          const p = api.tabs.remove(sender.tab.id);
          if (p && typeof p.catch === "function") {
            p.catch(() => {});
          }
        } catch (_) {}
      }
      if (typeof sendResponse === "function") {
        sendResponse({ closed: true });
      }
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
