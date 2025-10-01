const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
require("dotenv").config();

const app = express();
app.use(express.json());

const {
  PORT = 3000,
  APP_BASE_URL,
  HUBSPOT_CLIENT_ID,
  HUBSPOT_CLIENT_SECRET,
  HUBSPOT_REDIRECT_URI,
  STATE_HMAC_SECRET
} = process.env;

if (!HUBSPOT_CLIENT_ID || !HUBSPOT_CLIENT_SECRET || !HUBSPOT_REDIRECT_URI || !STATE_HMAC_SECRET) {
  console.error("Missing required env vars. Check .env");
  process.exit(1);
}

const TOKENS_FILE = "tokens.dev.json";
const tokenStore = fs.existsSync(TOKENS_FILE) ? JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8")) : {};
const saveTokens = () => fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokenStore, null, 2));

const base64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const signState = (obj) => {
  const payload = base64url(JSON.stringify(obj));
  const sig = crypto.createHmac("sha256", STATE_HMAC_SECRET).update(payload).digest("hex");
  return `${payload}.${sig}`;
};
const verifyState = (state) => {
  const [payload, sig] = (state || "").split(".");
  if (!payload || !sig) return null;
  const expected = crypto.createHmac("sha256", STATE_HMAC_SECRET).update(payload).digest("hex");
  if (sig !== expected) return null;
  const json = JSON.parse(Buffer.from(payload.replace(/-/g,"+").replace(/_/g,"/"), "base64").toString());
  if (Date.now() - json.ts > 10 * 60 * 1000) return null; // 10m TTL
  return json;
};

const OAUTH_AUTHORIZE = "https://app.hubspot.com/oauth/authorize";
const OAUTH_TOKEN = "https://api.hubapi.com/oauth/v1/token";

// Start OAuth: http://localhost:3000/hubspot/authorize?org_id=YOUR_ORG_ID
app.get("/hubspot/authorize", (req, res) => {
  const orgId = req.query.org_id || "demo-org";
  const state = signState({ org_id: orgId, ts: Date.now(), nonce: crypto.randomBytes(8).toString("hex") });
  const scopes = encodeURIComponent("crm.objects.contacts.read crm.objects.contacts.write");
  const url =
    `${OAUTH_AUTHORIZE}?client_id=${encodeURIComponent(HUBSPOT_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(HUBSPOT_REDIRECT_URI)}` +
    `&scope=${scopes}&state=${encodeURIComponent(state)}`;
  res.redirect(url);
});

// OAuth callback (configure this exact path in your HubSpot app)
app.get("/hubspot/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const parsed = verifyState(state);
    if (!code || !parsed) return res.status(400).send("Invalid or expired state/code");

    const form = new URLSearchParams({
      grant_type: "authorization_code",
      code: code.toString(),
      client_id: HUBSPOT_CLIENT_ID,
      client_secret: HUBSPOT_CLIENT_SECRET,
      redirect_uri: HUBSPOT_REDIRECT_URI
    });

    const tokenResp = await axios.post(OAUTH_TOKEN, form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 8000
    });

    const { access_token, refresh_token, expires_in, hub_id } = tokenResp.data;
    tokenStore[parsed.org_id] = {
      provider: "hubspot",
      hub_id,
      access_token,
      refresh_token,
      access_expires_at: Date.now() + (expires_in * 1000)
    };
    saveTokens();

    res.redirect(`${APP_BASE_URL}/ok?connected=hubspot&org=${encodeURIComponent(parsed.org_id)}`);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send("OAuth callback failed");
  }
});

// Ensure a valid token (refresh if expiring in ≤120s)
async function ensureToken(orgId) {
  const rec = tokenStore[orgId];
  if (!rec) throw new Error("No connection for org " + orgId);
  const expSoon = Date.now() > (rec.access_expires_at - 120 * 1000);
  if (!expSoon) return rec.access_token;

  const form = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: rec.refresh_token,
    client_id: HUBSPOT_CLIENT_ID,
    client_secret: HUBSPOT_CLIENT_SECRET
  });

  const resp = await axios.post(OAUTH_TOKEN, form, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 8000
  });

  rec.access_token = resp.data.access_token;
  rec.access_expires_at = Date.now() + (resp.data.expires_in * 1000);
  saveTokens();
  return rec.access_token;
}

// Test: create a contact in the connected portal
app.post("/hubspot/test", async (req, res) => {
  try {
    const orgId = req.query.org_id || "demo-org";
    const access = await ensureToken(orgId);

    const email = `buyerlink-test-${Date.now()}@example.com`;
    const payload = {
      properties: {
        email, firstname: "Buyerlink", lastname: "Test",
        lifecyclestage: "lead", lead_source: "buyerlink_local_dev"
      }
    };

    const r = await axios.post("https://api.hubapi.com/crm/v3/objects/contacts", payload, {
      headers: { Authorization: `Bearer ${access}` }, timeout: 8000
    });

    res.json({ ok: true, id: r.data.id, portal: tokenStore[orgId].hub_id, email });
  } catch (e) {
    console.error(e.response?.data || e.message);
    if (e.response?.status === 401) {
      try {
        const orgId = req.query.org_id || "demo-org";
        const access = await ensureToken(orgId);
        const email = `buyerlink-test-${Date.now()}@example.com`;
        const payload = { properties: { email, firstname: "Buyerlink", lastname: "Retry", lifecyclestage: "lead" } };
        const r = await axios.post("https://api.hubapi.com/crm/v3/objects/contacts", payload, {
          headers: { Authorization: `Bearer ${access}` }, timeout: 8000
        });
        return res.json({ ok: true, id: r.data.id, retried: true });
      } catch (e2) {
        console.error("Retry failed:", e2.response?.data || e2.message);
      }
    }
    res.status(500).json({ ok: false, error: e.response?.data || e.message });
  }
});

app.get("/ok", (req, res) => res.send("HubSpot connected. You can close this tab."));
app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Authorize URL: http://localhost:${PORT}/hubspot/authorize?org_id=demo-org`);
});