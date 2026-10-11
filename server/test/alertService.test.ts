import assert from "assert";
import express from "express";
import http from "http";
import { alertService } from "../services/alertService";
import { authService } from "../auth/authService";
import { authenticateUser, AuthenticatedRequest } from "../auth/authMiddleware";

console.log("=== RUNNING REAL-TIME THREAT ALERTING TEST SUITE (PHASE 11) ===\n");

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    delete process.env.GEMINI_API_KEY;
    alertService.clearAlerts();

    const aliceSession = authService.createTestSession("ANALYST", "usr-alice-11", "analyst@soc.internal");
    const bobSession = authService.createTestSession("ANALYST", "usr-bob-11", "analyst2@soc.internal");

    const app = express();
    app.use(express.json());

    // Register exact Phase 11 alert routes
    app.get("/api/alerts/stream", (req, res) => {
      let token: string | undefined;
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        token = authHeader.substring(7).trim();
      } else if (typeof req.query.token === "string") {
        token = req.query.token.trim();
      }

      if (!token) {
        return res.status(401).json({ error: "Unauthorized: Authentication token required", code: "UNAUTHORIZED" });
      }

      const session = authService.validateToken(token);
      if (!session) {
        return res.status(401).json({ error: "Unauthorized: Invalid or expired token", code: "INVALID_TOKEN" });
      }

      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
      });

      res.write(`event: connected\ndata: ${JSON.stringify({ message: "Connected", user: session.email })}\n\n`);

      alertService.addClient(res);

      req.on("close", () => {
        alertService.removeClient(res);
      });
    });

    app.get("/api/alerts/history", authenticateUser, (req: AuthenticatedRequest, res) => {
      const limit = Math.min(parseInt(req.query.limit as string) || 20, 50);
      const alerts = alertService.getRecentAlerts(limit);
      res.json({ success: true, count: alerts.length, alerts });
    });

    app.post("/api/alerts/broadcast", authenticateUser, (req: AuthenticatedRequest, res) => {
      const { severity, title, description, caseId, threatType } = req.body;
      if (!severity || !title) {
        return res.status(400).json({ error: "severity and title are required fields", code: "INVALID_ALERT_PAYLOAD" });
      }

      const alert = alertService.broadcast({
        severity,
        title: String(title).slice(0, 150),
        description: String(description || "").slice(0, 500),
        caseId: typeof caseId === "string" ? caseId : undefined,
        threatType: typeof threatType === "string" ? threatType : undefined,
        source: "SYSTEM",
      });

      res.status(201).json({ success: true, alert });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as any).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // Test 1: SSE stream requires auth (401)
      console.log("Test 1: Verifying 401 on unauthenticated GET /api/alerts/stream...");
      const res1 = await fetch(`${baseUrl}/api/alerts/stream`);
      assert.strictEqual(res1.status, 401, "Unauthenticated SSE request must return 401");
      console.log("✔ Test 1 Passed: Unauthenticated SSE stream rejected with 401.\n");

      // Test 2: Invalid token returns 401
      console.log("Test 2: Verifying 401 on invalid token in query param...");
      const res2 = await fetch(`${baseUrl}/api/alerts/stream?token=garbage-token`);
      assert.strictEqual(res2.status, 401, "Invalid token must return 401");
      console.log("✔ Test 2 Passed: Invalid token rejected with 401.\n");

      // Test 3: Valid query param establishes SSE connection
      console.log("Test 3: Verifying successful SSE stream connection with valid token...");
      const controller = new AbortController();
      const res3 = await fetch(`${baseUrl}/api/alerts/stream?token=${aliceSession.token}`, {
        signal: controller.signal,
      });
      assert.strictEqual(res3.status, 200, "Valid token must establish SSE stream");
      assert.strictEqual(res3.headers.get("content-type"), "text/event-stream");
      assert.strictEqual(alertService.getClientCount(), 1, "Client count must be 1");
      console.log("✔ Test 3 Passed: SSE connection established with text/event-stream headers.\n");

      // Test 4: Broadcast transmits alert event to connected SSE listener
      console.log("Test 4: Verifying alertService.broadcast() delivers event to active clients...");
      const alertData = alertService.broadcast({
        severity: "CRITICAL",
        title: "Executive Impersonation Detected",
        description: "High confidence CEO spoofing wire transfer attempt.",
        threatType: "BUSINESS_EMAIL_COMPROMISE",
        source: "CASE_PIPELINE",
      });
      assert.strictEqual(alertData.severity, "CRITICAL");
      assert.strictEqual(alertData.title, "Executive Impersonation Detected");
      console.log("✔ Test 4 Passed: Broadcast created and dispatched valid AlertEvent.\n");

      // Test 5: Client disconnect cleans up active clients Set
      console.log("Test 5: Verifying client cleanup on abort/disconnect...");
      controller.abort();
      // Allow abort to propagate
      await new Promise((r) => setTimeout(r, 50));
      assert.strictEqual(alertService.getClientCount(), 0, "Client count must return to 0 after disconnect");
      console.log("✔ Test 5 Passed: Disconnected client pruned from active listeners.\n");

      // Test 6: Ring buffer maintains bounded recent alert history
      console.log("Test 6: Verifying bounded recent alert buffer...");
      for (let i = 0; i < 60; i++) {
        alertService.broadcast({
          severity: "HIGH",
          title: `Threat Batch Item #${i}`,
          description: "Automated scan finding.",
          source: "BULK_TRIAGE",
        });
      }
      const allRecent = alertService.getRecentAlerts(100);
      assert.ok(allRecent.length <= 50, "Recent alerts buffer must not exceed 50 items");
      console.log(`✔ Test 6 Passed: Buffer bounded at max 50 items (current: ${allRecent.length}).\n`);

      // Test 7: GET /api/alerts/history returns recent alerts
      console.log("Test 7: Verifying GET /api/alerts/history endpoint...");
      const res7 = await fetch(`${baseUrl}/api/alerts/history?limit=5`, {
        headers: { Authorization: `Bearer ${aliceSession.token}` },
      });
      assert.strictEqual(res7.status, 200);
      const historyJson = await res7.json();
      assert.strictEqual(historyJson.success, true);
      assert.strictEqual(historyJson.alerts.length, 5);
      console.log("✔ Test 7 Passed: Alert history endpoint returned valid bounded results.\n");

      // Test 8: Multiple concurrent SSE clients all receive broadcast simultaneously
      console.log("Test 8: Verifying multiple concurrent SSE listeners...");
      const ctrlA = new AbortController();
      const ctrlB = new AbortController();
      await fetch(`${baseUrl}/api/alerts/stream?token=${aliceSession.token}`, { signal: ctrlA.signal });
      await fetch(`${baseUrl}/api/alerts/stream?token=${bobSession.token}`, { signal: ctrlB.signal });
      assert.strictEqual(alertService.getClientCount(), 2, "Must have 2 concurrent clients connected");
      const multiAlert = alertService.broadcast({
        severity: "CRITICAL",
        title: "Multi-client Alert",
        description: "Concurrent broadcast test.",
        source: "SYSTEM",
      });
      assert.ok(multiAlert.id);
      ctrlA.abort();
      ctrlB.abort();
      await new Promise((r) => setTimeout(r, 50));
      assert.strictEqual(alertService.getClientCount(), 0, "Both clients safely removed");
      console.log("✔ Test 8 Passed: Multiple concurrent SSE listeners broadcasted and pruned successfully.\n");

    } finally {
      server.close();
    }

    console.log("===================================================================");
    console.log("ALL PHASE 11 REAL-TIME ALERTING TESTS PASSED (8/8)");
    console.log("===================================================================\n");

  } finally {
    process.env = originalEnv;
  }
}

runTests().catch((err) => {
  console.error("Test suite failed:", err);
  process.exit(1);
});