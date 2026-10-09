import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE_NAME = "apex_session";
export const SESSION_TTL_SECONDS = 8 * 60 * 60;

export function createSessionToken(secret, nowSeconds = Math.floor(Date.now() / 1000)) {
  const expiresAt = nowSeconds + SESSION_TTL_SECONDS;
  const signature = createHmac("sha256", secret)
    .update(String(expiresAt))
    .digest("base64url");

  return `${expiresAt}.${signature}`;
}

export function isValidSessionToken(token, secret, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (typeof token !== "string") {
    return false;
  }

  const [expiresAtText, signature, ...extraParts] = token.split(".");
  if (
    extraParts.length > 0 ||
    !/^\d+$/.test(expiresAtText) ||
    !/^[\w-]+$/.test(signature || "")
  ) {
    return false;
  }

  const expiresAt = Number(expiresAtText);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= nowSeconds) {
    return false;
  }

  const expectedSignature = createHmac("sha256", secret)
    .update(expiresAtText)
    .digest("base64url");
  const actualDigest = createHash("sha256").update(signature).digest();
  const expectedDigest = createHash("sha256").update(expectedSignature).digest();

  return timingSafeEqual(actualDigest, expectedDigest);
}

export function getSessionToken(request) {
  const cookieHeader = request.headers.get("cookie") || "";
  for (const item of cookieHeader.split(";")) {
    const separator = item.indexOf("=");
    if (separator === -1 || item.slice(0, separator).trim() !== SESSION_COOKIE_NAME) {
      continue;
    }

    try {
      return decodeURIComponent(item.slice(separator + 1).trim());
    } catch {
      return null;
    }
  }

  return null;
}

export function isAuthenticated(request, secret) {
  return isValidSessionToken(getSessionToken(request), secret);
}

export function sessionCookie(token, request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${secure}`;
}

export function expiredSessionCookie(request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
}

export function jsonResponse(status, payload, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

export function constantTimeEquals(actual, expected) {
  const actualDigest = createHash("sha256").update(actual).digest();
  const expectedDigest = createHash("sha256").update(expected).digest();
  return timingSafeEqual(actualDigest, expectedDigest);
}
