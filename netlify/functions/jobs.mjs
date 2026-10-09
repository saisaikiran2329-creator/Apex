import { randomUUID } from "node:crypto";
import { getStore } from "@netlify/blobs";
import seedJobs from "../../jobs.json" with { type: "json" };
import {
  isAuthenticated,
  jsonResponse,
} from "./lib/auth.mjs";

const MAX_REQUEST_SIZE = 16_384;
const JOB_FIELDS = [
  ["title", 120],
  ["location", 120],
  ["employment_type", 80],
  ["description", 3000],
];

async function readJobs(store) {
  const jobs = await store.get("jobs", { type: "json" });
  const result = jobs === null ? seedJobs : jobs;
  if (!Array.isArray(result)) {
    throw new Error("Saved job postings have an invalid format.");
  }
  return result;
}

export default async function handler(request) {
  if (request.method !== "GET" && request.method !== "POST") {
    return jsonResponse(405, { error: "Method not allowed." }, { Allow: "GET, POST" });
  }

  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    console.error("Job posting requires the SESSION_SECRET environment variable.");
    return jsonResponse(503, { error: "Job posting service is not configured." });
  }

  if (request.method === "POST" && !isAuthenticated(request, sessionSecret)) {
    return jsonResponse(401, { error: "Sign in to post a job." });
  }

  let store;
  try {
    store = getStore({ name: "apex-job-postings", consistency: "strong" });
  } catch (error) {
    console.error("Could not connect to Netlify Blobs.", error);
    return jsonResponse(503, { error: "Job storage is unavailable." });
  }

  if (request.method === "GET") {
    try {
      return jsonResponse(200, { jobs: await readJobs(store) });
    } catch (error) {
      console.error("Could not load saved job postings.", error);
      return jsonResponse(500, { error: "Could not load saved job postings." });
    }
  }

  if (!request.headers.get("content-type")?.includes("application/json")) {
    return jsonResponse(415, { error: "Unsupported content type." });
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_REQUEST_SIZE) {
    return jsonResponse(413, { error: "Request is too large." });
  }

  let fields;
  try {
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > MAX_REQUEST_SIZE) {
      return jsonResponse(413, { error: "Request is too large." });
    }
    fields = JSON.parse(body);
  } catch {
    return jsonResponse(400, { error: "Request body must be valid JSON." });
  }

  if (
    !fields ||
    typeof fields !== "object" ||
    Array.isArray(fields) ||
    JOB_FIELDS.some(([name, maximum]) =>
      typeof fields[name] !== "string" ||
      !fields[name].trim() ||
      fields[name].trim().length > maximum
    )
  ) {
    return jsonResponse(400, {
      error: "Enter a job title, location, employment type, and description within the allowed lengths.",
    });
  }

  try {
    const jobs = await readJobs(store);
    const job = {
      id: randomUUID().replaceAll("-", ""),
      title: fields.title.trim(),
      location: fields.location.trim(),
      employment_type: fields.employment_type.trim(),
      description: fields.description.trim(),
      created_at: new Date().toISOString(),
    };
    jobs.unshift(job);
    await store.setJSON("jobs", jobs);
    return jsonResponse(201, { job });
  } catch (error) {
    console.error("Could not save the job posting.", error);
    return jsonResponse(500, { error: "Could not save the job posting." });
  }
}
