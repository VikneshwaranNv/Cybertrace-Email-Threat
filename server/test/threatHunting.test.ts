import assert from "assert";
import express from "express";
import http from "http";
import { threatHuntingService } from "../services/threatHuntingService";
import { caseService } from "../services/caseService";
import { authService } from "../auth/authService";
import { authenticateUser, AuthenticatedRequest } from "../auth/authMiddleware";

console.log("=== RUNNING THREAT HUNTING ENGINE TEST SUITE (PHASE 12) ===\n");

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    delete process.env.GEMINI_API_KEY;
    await caseService.initialize();

    // Setup users across roles
    const aliceSession = authService.createTestSession("ANALYST", "usr-alice-12", "analyst@soc.internal");
    const bobSession = authService.createTestSession("ANALYST", "usr-bob-12", "analyst2@soc.internal");
    const adminSession = authService.createTestSession("ADMIN", "usr-admin-12", "admin@soc.internal");
    const auditorSession = authService.createTestSession("AUDITOR", "usr-auditor-12", "auditor@soc.internal");

    // Create Alice private case with distinct IOC
    const aliceCase = await caseService.processEmail(
      "From: spearphish@apt-campaign.org\r\nTo: alice@victim.org\r\nSubject: Critical Security Advisory\r\nDate: Sun, 13 Sep 2026 12:00:00 +0000\r\nMessage-ID: <apt-12@apt-campaign.org>\r\n\r\nClick http://malicious-payload.net/login to reset your password immediately.",
      {
        title: "APT Spearphish Attack",
        ownerId: aliceSession.user.id,
        ownerEmail: aliceSession.user.email,
      }
    );

    // Create Bob private case
    const bobCase = await caseService.processEmail(
      "From: invoices@partner-billing.com\r\nTo: bob@victim.org\r\nSubject: Pending Invoice 9901\r\nDate: Sun, 13 Sep 2026 13:00:00 +0000\r\nMessage-ID: <inv-12@partner-billing.com>\r\n\r\nPlease check http://evil-billing-portal.com/view for your receipt.",
      {
        title: "Invoice Fraud Attack",
        ownerId: bobSession.user.id,
        ownerEmail: bobSession.user.email,
      }
    );

    const app = express();
    app.use(express.json());

    // Register exact Phase 12 Threat Hunting routes
    app.get("/api/hunt/search", authenticateUser, (req: AuthenticatedRequest, res) => {
      const user = req.user!;
      const q = typeof req.query.q === "string" ? req.query.q : undefined;
      const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
      const minRiskScore = req.query.minRiskScore ? parseInt(req.query.minRiskScore as string) : undefined;
      const maxRiskScore = req.query.maxRiskScore ? parseInt(req.query.maxRiskScore as string) : undefined;
      const fromDate = typeof req.query.fromDate === "string" ? req.query.fromDate : undefined;
      const toDate = typeof req.query.toDate === "string" ? req.query.toDate : undefined;

      let riskLevels: any[] | undefined;
      if (typeof req.query.riskLevels === "string") {
        riskLevels = req.query.riskLevels.split(",").map((s) => s.trim().toUpperCase());
      }

      let threatTypes: any[] | undefined;
      if (typeof req.query.threatTypes === "string") {
        threatTypes = req.query.threatTypes.split(",").map((s) => s.trim().toUpperCase());
      }

      const result = threatHuntingService.hunt(user, {
        q,
        riskLevels,
        threatTypes,
        minRiskScore,
        maxRiskScore,
        fromDate,
        toDate,
        limit,
      });
      res.json(result);
    });

    app.get("/api/hunt/ioc/:value", authenticateUser, (req: AuthenticatedRequest, res) => {
      const user = req.user!;
      const hit = threatHuntingService.lookupIoc(user, req.params.value);
      if (!hit) {
        return res.status(404).json({ error: "IOC not found", found: false });
      }
      res.json({ found: true, hit });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as any).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // Test 1: Unauthenticated request rejected with 401
      console.log("Test 1: Verifying 401 on unauthenticated GET /api/hunt/search...");
      const res1 = await fetch(`${baseUrl}/api/hunt/search`);
      assert.strictEqual(res1.status, 401, "Unauthenticated hunt search must return 401");
      console.log("✔ Test 1 Passed: Unauthenticated hunt search rejected with 401.\n");

      // Test 2: Invalid token returns 401
      console.log("Test 2: Verifying 401 on invalid Bearer token...");
      const res2 = await fetch(`${baseUrl}/api/hunt/search`, {
        headers: { Authorization: "Bearer bad-token" },
      });
      assert.strictEqual(res2.status, 401, "Invalid token must return 401");
      console.log("✔ Test 2 Passed: Invalid Bearer token rejected with 401.\n");

      // Test 3: Empty query returns accessible cases
      console.log("Test 3: Verifying empty query returns accessible cases...");
      const res3 = await fetch(`${baseUrl}/api/hunt/search`, {
        headers: { Authorization: `Bearer ${aliceSession.token}` },
      });
      assert.strictEqual(res3.status, 200);
      const data3 = await res3.json();
      assert.ok(data3.cases.length > 0, "Must return cases for Alice");
      assert.ok(data3.durationMs >= 0, "Must include query latency");
      console.log(`✔ Test 3 Passed: Query returned ${data3.cases.length} cases in ${data3.durationMs}ms.\n`);

      // Test 4: Keyword search matches subject, title, and domain
      console.log("Test 4: Verifying keyword search matches subject/title/domain...");
      const res4 = await fetch(`${baseUrl}/api/hunt/search?q=spearphish`, {
        headers: { Authorization: `Bearer ${aliceSession.token}` },
      });
      assert.strictEqual(res4.status, 200);
      const data4 = await res4.json();
      assert.ok(data4.cases.some((c: any) => c.caseId === aliceCase.caseRecord.caseId), "Alice case must match keyword");
      console.log("✔ Test 4 Passed: Keyword search successfully matched case metadata.\n");

      // Test 5: Defanged IOC input normalized and matched
      console.log("Test 5: Verifying defanged input (hxxp://...[.]) is normalized and matches...");
      const res5 = await fetch(`${baseUrl}/api/hunt/search?q=hxxp://malicious-payload[.]net`, {
        headers: { Authorization: `Bearer ${aliceSession.token}` },
      });
      assert.strictEqual(res5.status, 200);
      const data5 = await res5.json();
      assert.ok(data5.cases.some((c: any) => c.caseId === aliceCase.caseRecord.caseId), "Defanged IOC must match target case");
      console.log("✔ Test 5 Passed: Defanged indicator automatically refanged & correlated.\n");

      // Test 6: Risk level filter
      console.log("Test 6: Verifying riskLevel filter...");
      const res6 = await fetch(`${baseUrl}/api/hunt/search?riskLevels=LOW`, {
        headers: { Authorization: `Bearer ${aliceSession.token}` },
      });
      assert.strictEqual(res6.status, 200);
      const data6 = await res6.json();
      assert.ok(data6.cases.every((c: any) => c.severity === "LOW"), "All returned cases must be LOW severity");
      console.log("✔ Test 6 Passed: Risk level filter accurately scoped results.\n");

      // Test 7: Threat classification filter
      console.log("Test 7: Verifying threatTypes filter...");
      const res7 = await fetch(`${baseUrl}/api/hunt/search?threatTypes=PHISHING`, {
        headers: { Authorization: `Bearer ${aliceSession.token}` },
      });
      assert.strictEqual(res7.status, 200);
      const data7 = await res7.json();
      assert.ok(data7.cases.every((c: any) => c.classification === "PHISHING"), "All returned cases must match classification");
      console.log("✔ Test 7 Passed: Threat classification filter applied accurately.\n");

      // Test 8: Multi-tenant isolation (Bob cannot find Alice case)
      console.log("Test 8: Verifying multi-tenant isolation (Bob cannot hunt Alice cases)...");
      const res8 = await fetch(`${baseUrl}/api/hunt/search?q=spearphish`, {
        headers: { Authorization: `Bearer ${bobSession.token}` },
      });
      assert.strictEqual(res8.status, 200);
      const data8 = await res8.json();
      const foundAliceCase = data8.cases.some((c: any) => c.caseId === aliceCase.caseRecord.caseId);
      assert.strictEqual(foundAliceCase, false, "Bob must NEVER discover Alice case");
      console.log("✔ Test 8 Passed: Cross-tenant data isolation strictly enforced in threat hunt.\n");

      // Test 9: Admin has cross-tenant oversight
      console.log("Test 9: Verifying ADMIN role can hunt across all tenant cases...");
      const res9 = await fetch(`${baseUrl}/api/hunt/search?q=spearphish`, {
        headers: { Authorization: `Bearer ${adminSession.token}` },
      });
      assert.strictEqual(res9.status, 200);
      const data9 = await res9.json();
      assert.ok(data9.cases.some((c: any) => c.caseId === aliceCase.caseRecord.caseId), "Admin must discover Alice case");
      console.log("✔ Test 9 Passed: ADMIN role granted enterprise-wide hunt scope.\n");

      // Test 10: Auditor has read-only cross-tenant oversight
      console.log("Test 10: Verifying AUDITOR role can inspect hunt query results...");
      const res10 = await fetch(`${baseUrl}/api/hunt/search?q=spearphish`, {
        headers: { Authorization: `Bearer ${auditorSession.token}` },
      });
      assert.strictEqual(res10.status, 200);
      const data10 = await res10.json();
      assert.ok(data10.cases.some((c: any) => c.caseId === aliceCase.caseRecord.caseId), "Auditor must discover case for inspection");
      console.log("✔ Test 10 Passed: AUDITOR role granted read-only compliance hunt access.\n");

      // Test 11: Single IOC lookup endpoint
      console.log("Test 11: Verifying GET /api/hunt/ioc/:value direct lookup...");
      const res11 = await fetch(`${baseUrl}/api/hunt/ioc/apt-campaign.org`, {
        headers: { Authorization: `Bearer ${aliceSession.token}` },
      });
      assert.strictEqual(res11.status, 200);
      const data11 = await res11.json();
      assert.strictEqual(data11.found, true);
      assert.ok(data11.hit.defangedValue.includes("[.]"), "Hit must contain defanged representation");
      console.log("✔ Test 11 Passed: Single IOC lookup returned correlated case reference.\n");

      // Test 12: Bounded limit is respected
      console.log("Test 12: Verifying query limit parameter is bounded...");
      const res12 = await fetch(`${baseUrl}/api/hunt/search?limit=1`, {
        headers: { Authorization: `Bearer ${aliceSession.token}` },
      });
      assert.strictEqual(res12.status, 200);
      const data12 = await res12.json();
      assert.ok(data12.cases.length <= 1, "Results must respect limit=1");
      console.log("✔ Test 12 Passed: Result bounding and pagination limit respected.\n");

    } finally {
      server.close();
    }

    console.log("===================================================================");
    console.log("ALL PHASE 12 THREAT HUNTING TESTS PASSED (12/12)");
    console.log("===================================================================\n");

  } finally {
    process.env = originalEnv;
  }
}

runTests().catch((err) => {
  console.error("Test suite failed:", err);
  process.exit(1);
});