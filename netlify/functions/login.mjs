import {
  constantTimeEquals,
  createSessionToken,
  jsonResponse,
  sessionCookie,
} from "./lib/auth.mjs";

const MAX_REQUEST_SIZE = 16_384;

export default async function handler(request) {
  if (request.method !== "POST") {
    return jsonResponse(405, { error: "Method not allowed." }, { Allow: "POST" });
  }

  const email = process.env.LOGIN_EMAIL;
  const password = process.env.LOGIN_PASSWORD;
  const sessionSecret = process.env.SESSION_SECRET;
  if (!email || !password || !sessionSecret) {
    console.error("Login requires LOGIN_EMAIL, LOGIN_PASSWORD, and SESSION_SECRET environment variables.");
    return jsonResponse(503, { error: "Login service is not configured." });
  }

  if (!request.headers.get("content-type")?.includes("application/x-www-form-urlencoded")) {
    return jsonResponse(415, { error: "Unsupported content type." });
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_REQUEST_SIZE) {
    return jsonResponse(413, { error: "Request is too large." });
  }

  let body;
  try {
    body = await request.text();
  } catch (error) {
    console.error("Could not read login request.", error);
    return jsonResponse(400, { error: "Invalid login request." });
  }

  if (Buffer.byteLength(body, "utf8") > MAX_REQUEST_SIZE) {
    return jsonResponse(413, { error: "Request is too large." });
  }

  const fields = new URLSearchParams(body);
  const emails = fields.getAll("email");
  const passwords = fields.getAll("password");
  const authenticated =
    emails.length === 1 &&
    passwords.length === 1 &&
    constantTimeEquals(emails[0], email) &&
    constantTimeEquals(passwords[0], password);

  if (!authenticated) {
    return jsonResponse(401, { authenticated: false });
  }

  const token = createSessionToken(sessionSecret);
  return jsonResponse(
    200,
    { authenticated: true },
    { "Set-Cookie": sessionCookie(token, request) },
  );
}
