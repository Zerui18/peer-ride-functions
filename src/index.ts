
import * as admin from "firebase-admin";
import { setGlobalOptions } from "firebase-functions/v2/options";
import { beforeUserCreated } from "firebase-functions/v2/identity";
import { HttpsError, onCall } from "firebase-functions/v2/https";
import fetch from "node-fetch";

setGlobalOptions({ maxInstances: 10 });

admin.initializeApp();

const ALLOWED_DOMAINS_DOC_PATH = "config/emailDomains";
let cachedDomains: string[] | null = null;
let lastFetchMs = 0;
const CACHE_TTL_MS = 60_000;

async function getAllowedDomains(): Promise<string[]> {
  const now = Date.now();
  if (cachedDomains && now - lastFetchMs < CACHE_TTL_MS) {
    return cachedDomains;
  }

  const snapshot = await admin.firestore().doc(ALLOWED_DOMAINS_DOC_PATH).get();

  const domains = snapshot.get("domains");
  if (!Array.isArray(domains) || domains.some((item) => typeof item !== "string")) {
    throw new HttpsError(
        "failed-precondition",
        "Allowed email domains configuration is missing or invalid.",
    );
  }

  cachedDomains = domains.map((domain) => domain.toLowerCase().trim());
  lastFetchMs = now;
  return cachedDomains;
}

export const restrictUserSignupByDomain = beforeUserCreated(async (event) => {
  const user = event.data;

  if (!user || !user.email) {
    throw new HttpsError("invalid-argument", "Email is required for registration.");
  }

  const allowedDomains = await getAllowedDomains();
  const userDomain = user.email.split("@")[1]?.toLowerCase();

  if (!userDomain || !allowedDomains.includes(userDomain)) {
    throw new HttpsError(
        "permission-denied",
        `Unauthorized email domain "${userDomain ?? "unknown"}". Please use an allowed campus email.`,
    );
  }

  return;
});

const recaptchaSecret = process.env.RECAPTCHA_SECRET_KEY;
const recaptchaDisabled = process.env.RECAPTCHA_DISABLED === "true";

export const verifyRecaptcha = onCall(async (request) => {
  if (recaptchaDisabled) {
    return { success: true };
  }
  if (!recaptchaSecret) {
    throw new HttpsError("failed-precondition", "reCAPTCHA secret is not configured.");
  }

  const token = request.data?.token;
  const action = request.data?.action;

  if (!token || typeof token !== "string") {
    throw new HttpsError("invalid-argument", "reCAPTCHA token is required.");
  }

  const params = new URLSearchParams({
    secret: recaptchaSecret,
    response: token,
  });

  const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });

  if (!response.ok) {
    throw new HttpsError("unavailable", "Failed to verify reCAPTCHA token.");
  }

  const result = await response.json() as {
    success: boolean
    score?: number
    action?: string
    "error-codes"?: string[]
  };

  if (!result.success) {
    throw new HttpsError("permission-denied", "reCAPTCHA verification failed.");
  }

  if (typeof result.score === "number" && result.score < 0.5) {
    throw new HttpsError("permission-denied", "Suspicious activity detected. Please try again.");
  }

  if (action && result.action && result.action !== action) {
    throw new HttpsError("permission-denied", "reCAPTCHA action mismatch.");
  }

  return { success: true };
});
