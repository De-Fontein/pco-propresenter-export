// ==UserScript==
// @name         PCO ProPresenter Export
// @namespace    https://github.com/Auxority/pco-propresenter-export
// @version      0.5.0
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
  /* ============================
     Utilities
     ============================ */
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

  /* ============================
     OAuth helper (PKCE)
     ============================ */
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

  /* ============================
     Service API wrapper
     ============================ */
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

  /* ============================
     Exporter - main logic
     ============================ */
  class PCOExporter {
    constructor() {
      // Keep your client id & redirectUri as before
      this.clientId = "845585c27994617f1a04388f76f6457ce6b9b2cfbe01f5b2ed187f479223a7bf";
      this.scope = "services";
      this.redirectUri = "https://services.planningcenteronline.com/dashboard/0";
      this.tokenStoragePrefix = "pco_export_";
      // planId is derived at run time (when user selects the Tampermonkey menu command)
      this.planId = null;

      // Register Tampermonkey menu command (Button B)
      try {
        GM_registerMenuCommand("PCO Export — Start", () => this.startFromMenu());
      } catch (e) {
        console.warn("[PCO] GM_registerMenuCommand not available:", e);
      }

      // Listen for auth tab postMessage
      this.setupMessageListener();
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
        alert("PCO Export: Could not determine a plan ID from the current page. Open the plan page (URL should contain the plan ID) and run 'PCO Export — Start' again.");
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

    async _getStoredAccessToken() {
      return GM_getValue(this.tokenStoragePrefix + "access_token", "");
    }

    async _getStoredAccessTokenExpiry() {
      return GM_getValue(this.tokenStoragePrefix + "access_token_expires", 0);
    }

    async _getStoredRefreshToken() {
      return GM_getValue(this.tokenStoragePrefix + "refresh_token", "");
    }

    async _getStoredRefreshTokenExpiry() {
      return GM_getValue(this.tokenStoragePrefix + "refresh_token_expires", 0);
    }

    async getValidAccessToken() {
      const accessToken = await this._getStoredAccessToken();
      const accessExpiry = await this._getStoredAccessTokenExpiry();
      const now = Date.now();

      if (accessToken && accessExpiry && now < accessExpiry - 5000) {
        // still valid
        return accessToken;
      }

      // Try refresh flow
      const refreshToken = await this._getStoredRefreshToken();
      const refreshExpiry = await this._getStoredRefreshTokenExpiry();
      if (!refreshToken || now >= refreshExpiry) {
        // No refresh token or expired -> start full auth
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
        if (resp && resp.access_token) {
          this._saveTokenData(resp);
          return resp.access_token;
        } else {
          console.warn("[PCO] Refresh endpoint did not return access_token, starting full auth flow.");
          this._clearTokenData();
          const auth2 = new PCOAuth(this.clientId, this.redirectUri, this.scope);
          await auth2.startAuthFlow();
          return null;
        }
      } catch (e) {
        console.error("[PCO] Refresh token request failed:", e);
        this._clearTokenData();
        const auth = new PCOAuth(this.clientId, this.redirectUri, this.scope);
        await auth.startAuthFlow();
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
            const itemName = (item.attributes && (item.attributes.name || item.attributes.title)) ? (item.attributes.name || item.attributes.title) : `item-${item.id}`;
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

            const filename = this._sanitizeFilename(`${itemName}.txt`);
            const blob = new Blob([lyricsText], { type: "text/plain;charset=utf-8" });
            const url = URL.createObjectURL(blob);
            try {
              GM_download({
                url,
                name: filename,
                onerror: (err) => console.error("[PCO] GM_download error for", filename, err),
                onload: () => {
                  setTimeout(() => URL.revokeObjectURL(url), 2000);
                  console.debug("[PCO] Download queued:", filename);
                }
              });
            } catch (dlErr) {
              // Fallback: anchor download
              console.warn("[PCO] GM_download failed, falling back to anchor download", dlErr);
              const a = document.createElement("a");
              a.href = url;
              a.download = filename;
              document.body.appendChild(a);
              a.click();
              a.remove();
              setTimeout(() => URL.revokeObjectURL(url), 2000);
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

  /* ============================
     Initialization
     ============================ */
  const exporter = new PCOExporter();

  // If we are on the redirect URI page, post the code back and close
  if (window.location.pathname === "/dashboard/0") {
    exporter.handleRedirectTab();
  }
})();
