import {
  expiredSessionCookie,
  isAuthenticated,
  jsonResponse,
} from "./lib/auth.mjs";

export default async function handler(request) {
  if (request.method !== "GET") {
    return jsonResponse(405, { error: "Method not allowed." }, { Allow: "GET" });
  }

  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    console.error("Session validation requires the SESSION_SECRET environment variable.");
    return jsonResponse(503, { error: "Login service is not configured." });
  }

  if (isAuthenticated(request, sessionSecret)) {
    return jsonResponse(200, { authenticated: true });
  }

  return jsonResponse(401, { authenticated: false }, {
    "Set-Cookie": expiredSessionCookie(request),
  });
}
