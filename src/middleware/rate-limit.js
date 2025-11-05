/**
 * Simple in-memory rate limiter
 * Production-ready API protection without external dependencies
 */

const requestCounts = new Map();
const WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS = 30; // 30 requests per minute per IP

export function rateLimiter() {
  return async (c, next) => {
    const ip = c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || 'unknown';
    const now = Date.now();

    // Clean up old entries
    for (const [key, data] of requestCounts.entries()) {
      if (now - data.windowStart > WINDOW_MS) {
        requestCounts.delete(key);
      }
    }

    // Get or create rate limit data for this IP
    let rateLimitData = requestCounts.get(ip);

    if (!rateLimitData || now - rateLimitData.windowStart > WINDOW_MS) {
      // New window
      rateLimitData = {
        count: 0,
        windowStart: now
      };
      requestCounts.set(ip, rateLimitData);
    }

    // Increment request count
    rateLimitData.count++;

    // Check if rate limit exceeded
    if (rateLimitData.count > MAX_REQUESTS) {
      return c.json({
        error: 'Rate limit exceeded',
        message: `Maximum ${MAX_REQUESTS} requests per minute. Please try again later.`,
        retry_after: Math.ceil((WINDOW_MS - (now - rateLimitData.windowStart)) / 1000)
      }, 429);
    }

    // Add rate limit headers
    c.header('X-RateLimit-Limit', MAX_REQUESTS.toString());
    c.header('X-RateLimit-Remaining', (MAX_REQUESTS - rateLimitData.count).toString());
    c.header('X-RateLimit-Reset', new Date(rateLimitData.windowStart + WINDOW_MS).toISOString());

    await next();
  };
}
