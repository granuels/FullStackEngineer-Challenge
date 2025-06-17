import fs from "fs/promises";
import path from "path";
import { createHmac } from "crypto";

const DEBUG = false;
function debugLog(...args: any[]) {
  if (DEBUG) console.debug("[DEBUG]", ...args);
}

const FRONTEND_BASE = "https://challenge.sunvoy.com";
const API_BASE = "https://api.challenge.sunvoy.com";
const PATHS = {
  LOGIN: "/login",
  USERS: "/api/users",
  TOKENS: "/settings/tokens",
  SETTINGS: "/api/settings"
};
const CREDS = { username: "demo@example.org", password: "test" };
const HMAC_SECRET = "mys3cr3t";

const SESSION_FILE = path.join(process.cwd(), "session.json");
const OUTPUT_FILE = path.join(process.cwd(), "users.json");

interface Session {
  cookie: string;
  expires: string;
}

async function getSessionCookie(): Promise<string> {
  debugLog("\n==== STARTING SESSION CREATION ====");
  try {
    debugLog("Checking for existing session file...");
    const session = JSON.parse(await fs.readFile(SESSION_FILE, "utf8")) as Session;
    if (new Date(session.expires) > new Date()) {
      debugLog("Valid session found:", session.cookie.substring(0, 20) + "...");
      return session.cookie;
    }
    debugLog("Session expired");
  } catch (err) {
    debugLog("No session file found:", (err as Error).message);
  }

  debugLog("\n[1/3] Fetching login page for nonce...");
  const loginPage = await fetch(`${FRONTEND_BASE}${PATHS.LOGIN}`);
  debugLog("Login page status:", loginPage.status);

  const html = await loginPage.text();
  const nonce = /name="nonce" value="([^"]+)"/.exec(html)?.[1];
  debugLog("Extracted nonce:", nonce?.substring(0, 10) + "...");
  if (!nonce) throw new Error("Login nonce not found");

  debugLog("\n[2/3] Submitting login form...");
  const form = new URLSearchParams({ nonce, username: CREDS.username, password: CREDS.password });

  const res = await fetch(`${FRONTEND_BASE}${PATHS.LOGIN}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
    redirect: "manual"
  });
  debugLog("Login response status:", res.status);
  if (res.status !== 302) throw new Error(`Login failed with status ${res.status}`);

  debugLog("\n[3/3] Processing session cookies...");
  const cookies = res.headers.getSetCookie();
  const fullCookie = cookies
    .filter(c => c.includes("JSESSIONID") || c.includes("_csrf_token"))
    .map(c => c.split(";")[0])
    .join("; ");

  const expires = new Date(Date.now() + 86400 * 1000).toISOString();
  await fs.writeFile(SESSION_FILE, JSON.stringify({ cookie: fullCookie, expires }, null, 2));
  debugLog("New session created. Cookie length:", fullCookie.length);

  return fullCookie;
}

function signPayload(params: Record<string, string>): string {
  debugLog("\n==== PAYLOAD SIGNING ====");
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const payload: Record<string, string> = { ...params, timestamp };
  debugLog("Raw payload before signing:", payload);

  const payloadStr = Object.keys(payload)
    .sort()
    .map(k => `${k}=${encodeURIComponent(payload[k])}`)
    .join("&");
  debugLog("Sorted parameter string:", payloadStr);

  const checkcode = createHmac("sha1", HMAC_SECRET).update(payloadStr).digest("hex").toUpperCase();
  debugLog("Generated checkcode:", checkcode);

  const signed = `${payloadStr}&checkcode=${checkcode}`;
  debugLog("Final signed payload:", signed);

  return signed;
}

function extractTokens(html: string) {
  debugLog("\n==== TOKEN EXTRACTION ====");
  const extractToken = (label: string): string => {
    const patterns = [
      new RegExp(`${label}[^>]*>[^<]*<[^>]+>([^<]+)`),
      new RegExp(`${label}[^>]*>[^<]*<input[^>]+value="([^"]+)"`),
      new RegExp(`${label}[^>]*>([^<]+)<\\/code>`),
      new RegExp(`${label}[^>]*>[^<]*<td[^>]*>([^<]+)`)
    ];
    for (const pattern of patterns) {
      const match = pattern.exec(html);
      if (match && match[1]) {
        const value = match[1].trim();
        debugLog(`Extracted ${label}:`, value);
        return value;
      }
    }
    debugLog(`Token not found for: ${label}`);
    return "";
  };

  const tokens = {
    access_token: extractToken("Access Token:"),
    openId: extractToken("Open ID:"),
    userId: extractToken("User ID:"),
    apiuser: extractToken("API User:"),
    operateId: extractToken("Operate ID:"),
    language: extractToken("Language:") || "en_US"
  };
  debugLog("All extracted tokens:", tokens);
  return tokens;
}

async function getUsers(cookie: string) {
  debugLog("\n==== FETCHING USER LIST ====");
  const url = `${FRONTEND_BASE}${PATHS.USERS}`;
  debugLog("Requesting:", url);
  debugLog("Using cookie:", cookie.substring(0, 50) + "...");
  const res = await fetch(url, { method: "POST", headers: { Cookie: cookie } });
  debugLog("Response status:", res.status);
  if (!res.ok) throw new Error(`User fetch failed: ${res.status}`);
  const users = await res.json();
  debugLog(`Received ${users.length} users`);
  return users;
}

async function getCurrentUser(cookie: string) {
  debugLog("\n==== FETCHING CURRENT USER ====");
  debugLog("[1/4] Loading tokens page...");
  const tokensPage = await fetch(`${FRONTEND_BASE}${PATHS.TOKENS}`, { headers: { Cookie: cookie } });
  debugLog("Tokens page status:", tokensPage.status);
  const html = await tokensPage.text();

  if (!html.includes("Access Token:") || !html.includes("User ID:")) {
    throw new Error("Tokens page has unexpected structure");
  }

  debugLog("[2/4] Extracting tokens...");
  const tokens = extractTokens(html);
  if (!tokens.access_token || !tokens.userId) throw new Error("Required tokens missing");

  debugLog("[3/4] Signing payload...");
  const body = signPayload(tokens);

  debugLog("[4/4] Making API call...");
  const apiUrl = `${API_BASE}${PATHS.SETTINGS}`;
  const startTime = Date.now();
  const res = await fetch(apiUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: FRONTEND_BASE,
      Referer: `${FRONTEND_BASE}/`
    },
    body
  });
  const duration = Date.now() - startTime;
  debugLog(`API Response (${duration}ms):`, { status: res.status });

  if (!res.ok) throw new Error(`Settings API failed: ${res.status}`);
  const data = await res.json();
  debugLog("Current user data:", data);
  return data;
}

(async () => {
  try {
    debugLog("\n==== SCRIPT STARTED ====");
    debugLog("\n[PHASE 1] Authenticating...");
    const cookie = await getSessionCookie();
    debugLog("\n[PHASE 2] Fetching user list...");
    const users = await getUsers(cookie);
    debugLog("\n[PHASE 3] Fetching current user...");
    const currentUser = await getCurrentUser(cookie);
    debugLog("\n[PHASE 4] Saving results...");
    const allUsers = [...users, currentUser];
    await fs.writeFile(OUTPUT_FILE, JSON.stringify(allUsers, null, 2));
    debugLog("\n==== COMPLETED SUCCESSFULLY ====");
    console.log(`Success! Saved ${allUsers.length} users to ${OUTPUT_FILE}`);
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    debugLog("\n!! SCRIPT FAILED !!");
    console.error(" Error:", error.message);
    process.exit(1);
  }
})();
