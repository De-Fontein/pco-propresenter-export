// ==UserScript==
// @name         PCO ProPresenter Export
// @namespace    https://github.com/Auxority/pco-propresenter-export
// @version      0.6.0
// @description  Export PCO service plan arrangement lyrics as .txt files. Tampermonkey menu trigger, PKCE OAuth, token storage & refresh.
// @match        https://services.planningcenteronline.com/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_xmlhttpRequest
// @grant        GM_registerMenuCommand
// @grant        GM_download
// @updateURL    https://raw.githubusercontent.com/De-Fontein/pco-propresenter-export/refs/heads/main/index.user.js
// @downloadURL  https://raw.githubusercontent.com/De-Fontein/pco-propresenter-export/refs/heads/main/index.user.js
// ==/UserScript==

(async () => {
  class PKCEUtils {
    static generateVerifier(length = 64) {
      const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
      let result = "";
      const random = new Uint8Array(length);
      crypto.getRandomValues(random);
      random.forEach(x => result += charset[x % charset.length]);
      return result;
    }

    static async generateChallenge(verifier) {
      const data = new TextEncoder().encode(verifier);
      const hash = await crypto.subtle.digest("SHA-256", data);
      return btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    }
  }

  class PCOAuth {
    constructor(clientId, redirectUri, scope) {
      this.clientId = clientId;
      this.redirectUri = redirectUri;
      this.scope = scope;
    }

    async startAuthFlow() {
      const verifier = PKCEUtils.generateVerifier();
      const challenge = await PKCEUtils.generateChallenge(verifier);
      sessionStorage.setItem("pco_code_verifier", verifier);

      const authUrl =
        `https://api.planningcenteronline.com/oauth/authorize` +
        `?client_id=${encodeURIComponent(this.clientId)}` +
        `&response_type=code` +
        `&redirect_uri=${encodeURIComponent(this.redirectUri)}` +
        `&scope=${encodeURIComponent(this.scope)}` +
        `&code_challenge=${encodeURIComponent(challenge)}` +
        `&code_challenge_method=S256`;

      console.debug("[PCO] Opening auth tab…");
      window.open(authUrl, "_blank");
    }

    async exchangeCodeForToken(code) {
      const verifier = sessionStorage.getItem("pco_code_verifier") || "";
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: this.redirectUri,
        client_id: this.clientId,
        code_verifier: verifier
      });

      return new Promise((resolve, reject) => {
        GM_xmlhttpRequest({
          method: "POST",
          url: "https://api.planningcenteronline.com/oauth/token",
          data: body.toString(),
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          onload: res => {
            try {
              const data = JSON.parse(res.responseText);
              resolve(data);
            } catch (e) {
              reject(e);
            }
          },
          onerror: err => reject(err)
        });
      });
    }

    async refreshAccessToken(refreshToken) {
      const body = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: this.clientId
      });

      return new Promise((resolve, reject) => {
        GM_xmlhttpRequest({
          method: "POST",
          url: "https://api.planningcenteronline.com/oauth/token",
          data: body.toString(),
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          onload: res => {
            try {
              const data = JSON.parse(res.responseText);
              resolve(data);
            } catch (e) {
              reject(e);
            }
          },
          onerror: err => reject(err)
        });
      });
    }
  }

  class PCOServiceAPI {
    constructor(accessToken) {
      this.accessToken = accessToken;
    }

    async fetchPlanItems(planId, serviceTypeId = "1557519", perPage = 100) {
      // include=arrangement ensures the arrangements are returned in `included`
      const url = `https://api.planningcenteronline.com/services/v2/service_types/${serviceTypeId}/plans/${planId}/items?per_page=${perPage}&include=arrangement`;

      return new Promise((resolve, reject) => {
        GM_xmlhttpRequest({
          method: "GET",
          url,
          headers: { Authorization: `Bearer ${this.accessToken}` },
          onload: r => {
            try {
              resolve(JSON.parse(r.responseText));
            } catch (e) {
              reject(e);
            }
          },
          onerror: err => reject(err)
        });
      });
    }
  }

  class ProPresenterExporter {
    constructor() {
      this.clientId = "845585c27994617f1a04388f76f6457ce6b9b2cfbe01f5b2ed187f479223a7bf";
      this.scope = "services";
      this.redirectUri = "https://services.planningcenteronline.com/dashboard/0";
      this.tokenStoragePrefix = "pp_export_";
      this.planId = null;
    }

    init() {
      // Register Tampermonkey menu command (Button B)
      try {
        GM_registerMenuCommand("PP Export — Start", () => this.startFromMenu());
      } catch (e) {
        console.warn("[PP] GM_registerMenuCommand not available:", e);
      }

      this.startButtonPolling();

      // Listen for auth tab postMessage
      this.setupMessageListener();
    }

    startButtonPolling() {
      if (this.buttonPollIntervalId) return; // avoid duplicate intervals

      this.buttonPollIntervalId = setInterval(() => {
        try {
          // If our button is already present, nothing to do this tick
          if (document.querySelector("#pp-export-button")) {
            return;
          }

          // Try to find the host button again on the current SPA view
          const originalButton = document.querySelector(
            'button[data-testid="order-add-plan-element"]'
          );
          if (!originalButton || !originalButton.parentNode) {
            return; // still not on a plan page or UI not ready
          }

          // Host button exists and our button does not -> inject
          this.injectExportButton(originalButton);
        } catch (e) {
          console.warn("[PP] Error during button polling:", e);
        }
      }, 1000); // every 1s; tweak if desired
    }

    injectExportButton(originalButton) {
      try {
        // Safety: if button already exists, skip
        if (document.querySelector("#pp-export-button")) return;

        const exportButton = originalButton.cloneNode(true);
        exportButton.id = "pp-export-button";
        exportButton.innerText = "ProPresenter Export";
        exportButton.setAttribute("aria-label", "ProPresenter Export");
        exportButton.style.backgroundColor = "";
        exportButton.style.background = "linear-gradient(71deg, #ff6c1a 0%, #ffa235 100%)";
        exportButton.style.color = "white";
        exportButton.style.fontWeight = "bold";

        exportButton.addEventListener("click", async (e) => {
          e.preventDefault();
          e.stopPropagation();
          this.planId = this._derivePlanIdFromPath(window.location.pathname);
          await this.performExportFlow();
        });

        originalButton.parentNode.prepend(exportButton);
      } catch (err) {
        console.warn("[PP] Failed to inject export button:", err);
      }
    }

    _derivePlanIdFromPath(pathname) {
      const parts = pathname.split('/');
      const last = parts.pop() || "";
      if (/^\d+$/.test(last)) return last;
      const plansIdx = pathname.indexOf("/plans/");
      if (plansIdx !== -1) {
        const after = pathname.slice(plansIdx + 7).split('/')[0];
        if (after) return after;
      }
      return null;
    }

    async startFromMenu() {
      this.planId = this._derivePlanIdFromPath(window.location.pathname);
      if (!this.planId) {
        alert("PP Export: Could not determine a plan ID from the current page. Open the plan page (URL should contain the plan ID) and run 'PP Export — Start' again.");
        return;
      }

      await this.performExportFlow();
    }

    // Token storage helpers
    _saveTokenData(tokenResponse) {
      const now = Date.now();
      if (tokenResponse.access_token) {
        GM_setValue(this.tokenStoragePrefix + "access_token", tokenResponse.access_token);
        const expiresMs = tokenResponse.expires_in ? now + (tokenResponse.expires_in * 1000) : now + (60 * 60 * 1000);
        GM_setValue(this.tokenStoragePrefix + "access_token_expires", expiresMs);
      }
      if (tokenResponse.refresh_token) {
        GM_setValue(this.tokenStoragePrefix + "refresh_token", tokenResponse.refresh_token);
        const refreshExpiryMs = tokenResponse.refresh_token_expires_in ? now + (tokenResponse.refresh_token_expires_in * 1000) : now + (30 * 24 * 60 * 60 * 1000);
        GM_setValue(this.tokenStoragePrefix + "refresh_token_expires", refreshExpiryMs);
      }
    }

    _clearTokenData() {
      GM_setValue(this.tokenStoragePrefix + "access_token", "");
      GM_setValue(this.tokenStoragePrefix + "access_token_expires", 0);
      GM_setValue(this.tokenStoragePrefix + "refresh_token", "");
      GM_setValue(this.tokenStoragePrefix + "refresh_token_expires", 0);
    }

    async getValidAccessToken() {
      const now = Date.now();

      // Direct read from GM storage
      const accessToken = GM_getValue(this.tokenStoragePrefix + "access_token", "");
      const accessExpiry = GM_getValue(this.tokenStoragePrefix + "access_token_expires", 0);

      if (accessToken && accessExpiry && now < accessExpiry - 5000) {
        return accessToken;
      }

      const refreshToken = GM_getValue(this.tokenStoragePrefix + "refresh_token", "");
      const refreshExpiry = GM_getValue(this.tokenStoragePrefix + "refresh_token_expires", 0);

      if (!refreshToken || now >= refreshExpiry) {
        console.debug("[PCO] Refresh token missing or expired; starting full auth flow.");
        this._clearTokenData();
        const auth = new PCOAuth(this.clientId, this.redirectUri, this.scope);
        await auth.startAuthFlow();
        return null;
      }

      try {
        console.debug("[PCO] Attempting to refresh access token...");
        const auth = new PCOAuth(this.clientId, this.redirectUri, this.scope);
        const resp = await auth.refreshAccessToken(refreshToken);

        if (resp?.access_token) {
          this._saveTokenData(resp);
          return resp.access_token;
        }

        console.warn("[PCO] Refresh endpoint returned no access_token; starting full auth flow.");
        this._clearTokenData();
        await new PCOAuth(this.clientId, this.redirectUri, this.scope).startAuthFlow();
        return null;

      } catch (e) {
        console.error("[PCO] Refresh token request failed:", e);
        this._clearTokenData();
        await new PCOAuth(this.clientId, this.redirectUri, this.scope).startAuthFlow();
        return null;
      }
    }

    setupMessageListener() {
      window.addEventListener("message", async event => {
        if (event.origin !== "https://services.planningcenteronline.com") return;

        const { code } = event.data;
        if (!code) return;

        console.debug("[PCO] Code received from auth tab:", code);
        const auth = new PCOAuth(this.clientId, this.redirectUri, this.scope);
        try {
          const tokenResponse = await auth.exchangeCodeForToken(code);
          if (!tokenResponse || !tokenResponse.access_token) throw new Error("No access token in token response");

          this._saveTokenData(tokenResponse);

          // If the user previously invoked export and we have a planId, continue
          if (!this.planId) {
            this.planId = this._derivePlanIdFromPath(window.location.pathname);
          }
          if (this.planId) {
            await this.performExportWithAccessToken(tokenResponse.access_token);
          } else {
            alert("PCO Export: Authentication completed. Navigate to the plan page and run 'PCO Export — Start' from the Tampermonkey menu.");
          }
        } catch (err) {
          console.error("[PCO] Failed to exchange code for tokens:", err);
          alert("PCO Export: Failed to complete authentication. See console for details.");
        }
      });
    }

    handleRedirectTab() {
      // If script runs on the redirect URI, post the code back to opener and close
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get("code");
      if (code && window.opener) {
        window.opener.postMessage({ code }, "https://services.planningcenteronline.com");
        try { window.close(); } catch (e) { /* ignore */ }
      }
    }

    async performExportFlow() {
      const accessToken = await this.getValidAccessToken();
      if (!accessToken) {
        // Auth flow started in new tab; message listener will continue when auth completes.
        return;
      }
      await this.performExportWithAccessToken(accessToken);
    }

    async performExportWithAccessToken(accessToken) {
      if (!this.planId) {
        this.planId = this._derivePlanIdFromPath(window.location.pathname);
        if (!this.planId) {
          alert("PCO Export: Can't determine plan ID. Open the plan page and run 'PCO Export — Start' again.");
          return;
        }
      }

      const api = new PCOServiceAPI(accessToken);
      try {
        console.debug("[PCO] Fetching plan items for plan", this.planId);
        const itemsResponse = await api.fetchPlanItems(this.planId);
        console.debug("[PCO] Plan items response:", itemsResponse);

        const included = itemsResponse.included || [];
        const items = itemsResponse.data || [];

        // Build arrangement lookup table from included[] using the exact type "Arrangement"
        const arrangements = {};
        for (const inc of included) {
          if (!inc || !inc.type || !inc.id) continue;
          // Match type exactly "Arrangement" (per your example)
          if (inc.type === "Arrangement") {
            arrangements[inc.id] = inc;
          }
        }

        // For each item, look up its arrangement by id in the arrangements map and export lyrics from arrangement.attributes.lyrics
        for (const item of items) {
          try {
            const name = item.attributes && (item.attributes.name || item.attributes.title);
            const itemName = name ? name : `item-${item.id}`;
            const arrId = item.relationships?.arrangement?.data?.id;
            if (!arrId) {
              // Per your instruction: don't warn; skip silently
              continue;
            }

            const arrangement = arrangements[arrId];
            if (!arrangement) {
              // Not found in included[] - skip silently
              continue;
            }

            const rawLyrics = arrangement.attributes?.lyrics;
            if (!rawLyrics) {
              // No lyrics field - skip silently (you said all arrangements contain lyrics)
              continue;
            }

            // Normalize CRLF -> LF (and trim)
            const lyricsText = String(rawLyrics).replace(/\r\n/g, "\n").trim();
            if (!lyricsText) continue;

            const filename = this._sanitizeFilename(`${itemName}`);
            const blob = new Blob([lyricsText], { type: "text/plain;charset=utf-8" });
            const url = URL.createObjectURL(blob);
            try {
              GM_download({
                url,
                name: filename,
                onerror: (err) => {
                  URL.revokeObjectURL(url);
                  console.error("[PCO] GM_download error for", filename, err);
                },
                onload: () => {
                  URL.revokeObjectURL(url);
                  setTimeout(() => URL.revokeObjectURL(url), 2000);
                  console.debug("[PCO] Download queued:", filename);
                }
              });
            } catch (dlErr) {
              console.warn("[PCO] GM_download failed", dlErr);
            }
          } catch (itemErr) {
            console.error("[PCO] Error processing item", item, itemErr);
          }
        }

        alert("PCO Export: Lyrics export queued for download (one .txt per arrangement). Check your browser's downloads.");
      } catch (err) {
        console.error("[PCO] Failed to fetch plan items or export:", err);
        alert("PCO Export: Failed to fetch plan items. See console for details.");
      }
    }

    _sanitizeFilename(name) {
      return String(name).replace(/[\/\\?%*:|"<>]/g, "-").slice(0, 200);
    }
  }

  function main() {
    const exporter = new ProPresenterExporter();
    exporter.init();

    // If we are on the redirect URI page, post the code back and close
    if (window.location.pathname === "/dashboard/0") {
      exporter.handleRedirectTab();
    }
  }

  main();
})();
