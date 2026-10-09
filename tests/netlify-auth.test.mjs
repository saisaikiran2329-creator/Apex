import assert from "node:assert/strict";
import test from "node:test";
import {
  createSessionToken,
  isValidSessionToken,
  SESSION_TTL_SECONDS,
} from "../netlify/functions/lib/auth.mjs";
import loginHandler from "../netlify/functions/login.mjs";
import sessionHandler from "../netlify/functions/session.mjs";
import jobsHandler from "../netlify/functions/jobs.mjs";

test("session token is accepted with the correct secret before expiry", () => {
  const now = 1_800_000_000;
  const token = createSessionToken("test-secret", now);

  assert.equal(isValidSessionToken(token, "test-secret", now + 1), true);
});

test("session token is rejected after expiry", () => {
  const now = 1_800_000_000;
  const token = createSessionToken("test-secret", now);

  assert.equal(isValidSessionToken(token, "test-secret", now + SESSION_TTL_SECONDS), false);
});

test("session token is rejected for a different secret or modified signature", () => {
  const token = createSessionToken("test-secret", 1_800_000_000);
  const [expiresAt, signature] = token.split(".");
  const modifiedToken = `${expiresAt}.${signature.slice(1)}`;

  assert.equal(isValidSessionToken(token, "wrong-secret", 1_800_000_001), false);
  assert.equal(isValidSessionToken(modifiedToken, "test-secret", 1_800_000_001), false);
});

test("successful login issues a secure session that the session endpoint accepts", async () => {
  const originalEnvironment = {
    email: process.env.LOGIN_EMAIL,
    password: process.env.LOGIN_PASSWORD,
    secret: process.env.SESSION_SECRET,
  };
  process.env.LOGIN_EMAIL = "admin@example.com";
  process.env.LOGIN_PASSWORD = "correct-password";
  process.env.SESSION_SECRET = "test-session-secret";

  try {
    const loginResponse = await loginHandler(new Request("https://example.com/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        email: "admin@example.com",
        password: "correct-password",
      }),
    }));
    assert.equal(loginResponse.status, 200);
    assert.match(loginResponse.headers.get("set-cookie"), /HttpOnly/);
    assert.match(loginResponse.headers.get("set-cookie"), /Secure/);

    const sessionResponse = await sessionHandler(new Request("https://example.com/api/session", {
      headers: { Cookie: loginResponse.headers.get("set-cookie").split(";")[0] },
    }));
    assert.equal(sessionResponse.status, 200);
    assert.deepEqual(await sessionResponse.json(), { authenticated: true });
  } finally {
    for (const [name, value] of [
      ["LOGIN_EMAIL", originalEnvironment.email],
      ["LOGIN_PASSWORD", originalEnvironment.password],
      ["SESSION_SECRET", originalEnvironment.secret],
    ]) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
});

test("job publishing rejects requests without a valid session", async () => {
  const originalSecret = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = "test-session-secret";

  try {
    const response = await jobsHandler(new Request("https://example.com/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "Recruiter",
        location: "Bengaluru",
        employment_type: "Full-time",
        description: "Recruit candidates.",
      }),
    }));
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "Sign in to post a job." });
  } finally {
    if (originalSecret === undefined) {
      delete process.env.SESSION_SECRET;
    } else {
      process.env.SESSION_SECRET = originalSecret;
    }
  }
});
