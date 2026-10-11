import { GoogleGenAI } from '@google/genai';

/**
 * Shared Gemini client management with intelligent rate-limit circuit breaking,
 * quota cooldown tracking, and graceful fallback handling.
 */
let cachedClient: GoogleGenAI | null = null;
let lastApiKey: string | undefined = undefined;

let quotaCooldownUntil = 0;
let lastQuotaNoticeTime = 0;

export function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey.trim() === '') {
    return null;
  }

  if (cachedClient && lastApiKey === apiKey) {
    return cachedClient;
  }

  try {
    cachedClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
    lastApiKey = apiKey;
    return cachedClient;
  } catch (err) {
    console.warn('[Gemini Client] Initialization notice:', (err as any)?.message || err);
    return null;
  }
}

/**
 * Checks whether the Gemini API is configured and outside any rate-limit / quota cooldown period.
 */
export function isGeminiAvailable(): boolean {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey.trim() === '') {
    return false;
  }

  if (Date.now() < quotaCooldownUntil) {
    return false;
  }

  return true;
}

/**
 * Records a quota exhaustion or rate limit (HTTP 429) event, activating the circuit breaker.
 */
export function recordGeminiQuotaExceeded(err: any): number {
  let delayMs = 30000; // Default 30s cooldown

  try {
    const errString = typeof err === 'string' ? err : JSON.stringify(err?.message || err?.error || err || '');
    
    // Check for retryDelay in details or message (e.g. "retryDelay": "15s" or "Please retry in 15.8s")
    const retryMatch = errString.match(/retryDelay"?:\s*"(\d+)s/i) || errString.match(/retry in ([\d.]+)s/i);
    if (retryMatch && retryMatch[1]) {
      const parsedSec = parseFloat(retryMatch[1]);
      if (!isNaN(parsedSec) && parsedSec > 0) {
        delayMs = Math.ceil((parsedSec + 2) * 1000);
      }
    }
  } catch {
    // Keep default 30s
  }

  quotaCooldownUntil = Date.now() + delayMs;

  // Rate-limit console logs to once per 15s to keep logs clean
  if (Date.now() - lastQuotaNoticeTime > 15000) {
    lastQuotaNoticeTime = Date.now();
    console.info(
      `[Gemini AI] Quota limit active (429 Resource Exhausted). Operating in deterministic forensic heuristic fallback mode (cooling down for ${Math.ceil(
        delayMs / 1000
      )}s).`
    );
  }

  return delayMs;
}

/**
 * Helper to identify if an error is a rate limit or quota exhaustion (429 / RESOURCE_EXHAUSTED).
 */
export function isQuotaExceededError(err: any): boolean {
  if (!err) return false;
  if (err.status === 429 || err.code === 429) return true;

  const msg = (err.message || String(err)).toLowerCase();
  return (
    msg.includes('429') ||
    msg.includes('resource_exhausted') ||
    msg.includes('quota exceeded') ||
    msg.includes('rate limit')
  );
}
