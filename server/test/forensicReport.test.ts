import assert from "assert";
import express from "express";
import http from "http";
import { caseService } from "../services/caseService";
import { authService } from "../auth/authService";
import { authenticateUser, AuthenticatedRequest } from "../auth/authMiddleware";
import { auditLogger } from "../auth/auditLogger";

console.log("=== RUNNING FORENSIC REPORT EXPORT TEST SUITE (PHASE 10) ===\n");

async function runTests() {
  const originalEnv = { ...process.env };

  try {
    delete process.env.GEMINI_API_KEY;

    await caseService.initialize();

    const aliceSession = authService.createTestSession("ANALYST", "usr-alice-10", "analyst@soc.internal");
    const bobSession = authService.createTestSession("ANALYST", "usr-bob-10", "analyst2@soc.internal");
    const auditorSession = authService.createTestSession("AUDITOR", "usr-auditor-10", "auditor@soc.internal");

    const aliceCase = await caseService.processEmail(
      "From: attacker@evil.com\r\nTo: alice@victim.org\r\nSubject: Urgent Wire Transfer\r\nDate: Sun, 13 Sep 2026 10:00:00 +0000\r\nMessage-ID: <wire-10@evil.com>\r\n\r\nPlease transfer $50,000 immediately.",
      {
        title: "Wire Transfer Phish",
        ownerId: aliceSession.user.id,
        ownerEmail: aliceSession.user.email,
      }
    );

    const app = express();
    app.use(express.json());

    app.get("/api/cases/:id/report", authenticateUser, (req: AuthenticatedRequest, res) => {
      const user = req.user!;
      const caseId = req.params.id;

      const access = caseService.canUserAccessCase(user, caseId);
      if (!access.caseFound) return res.status(404).json({ error: "Case not found" });
      if (!access.allowed) {
        auditLogger.record({
          action: "AUTHORIZATION_FAILURE",
          status: "DENIED",
          actorId: user.userId,
          actorEmail: user.email,
          actorRole: user.role,
          resourceId: caseId,
          details: "Unauthorized forensic report generation attempt on " + caseId,
        });
        return res.status(403).json({ error: "Forbidden: You do not have permission to access reports for this case" });
      }

      const report = caseService.generateReport(caseId);
      if (!report) return res.status(404).json({ error: "Case not found" });

      auditLogger.record({
        action: "REPORT_GENERATED",
        status: "SUCCESS",
        actorId: user.userId,
        actorEmail: user.email,
        actorRole: user.role,
        resourceId: caseId,
        details: "Forensic DFIR report generated for case " + caseId + " by " + user.email,
      });

      res.json(report);
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as any).port;
    const baseUrl = "http://127.0.0.1:" + port;

    try {
      console.log("Test 1: Verifying 401 Unauthorized on unauthenticated GET /api/cases/:id/report...");
      const res1 = await fetch(baseUrl + "/api/cases/" + aliceCase.caseRecord.caseId + "/report");
      assert.strictEqual(res1.status, 401, "Unauthenticated report access must return 401");
      console.log("✔ Test 1 Passed: Unauthenticated report query rejected with 401.\n");

      console.log("Test 2: Verifying 401 on invalid/malformed Bearer token...");
      const res2 = await fetch(baseUrl + "/api/cases/" + aliceCase.caseRecord.caseId + "/report", {
        headers: { Authorization: "Bearer invalid-token-xyz" },
      });
      assert.strictEqual(res2.status, 401, "Invalid token must return 401");
      console.log("✔ Test 2 Passed: Invalid Bearer token rejected with 401.\n");

      console.log("Test 3: Verifying 404 on non-existent case ID...");
      const res3 = await fetch(baseUrl + "/api/cases/CASE-NON-EXISTENT/report", {
        headers: { Authorization: "Bearer " + aliceSession.token },
      });
      assert.strictEqual(res3.status, 404, "Non-existent case must return 404");
      console.log("✔ Test 3 Passed: Non-existent case report query returns 404.\n");

      console.log("Test 4: Verifying authorized case owner gets complete forensic report schema...");
      const res4 = await fetch(baseUrl + "/api/cases/" + aliceCase.caseRecord.caseId + "/report", {
        headers: { Authorization: "Bearer " + aliceSession.token },
      });
      assert.strictEqual(res4.status, 200, "Authorized owner must receive 200");
      const report = await res4.json();
      assert.ok(report.reportId, "Report must contain reportId");
      assert.strictEqual(report.caseRecord.caseId, aliceCase.caseRecord.caseId, "Report must match caseId");
      assert.ok(report.threatAssessment, "Report must contain threatAssessment");
      assert.ok(report.riskScore, "Report must contain riskScore");
      assert.ok(Array.isArray(report.structuredSections), "Report must contain structuredSections array");
      assert.strictEqual(report.structuredSections.length, 18, "Report must contain exactly 18 formatted sections");
      assert.ok(report.legalDisclaimer, "Report must include legal disclaimer");
      console.log("✔ Test 4 Passed: Case owner successfully retrieved complete 18-section forensic report.\n");

      console.log("Test 5: Verifying AUDITOR role has read access to forensic report...");
      const res5 = await fetch(baseUrl + "/api/cases/" + aliceCase.caseRecord.caseId + "/report", {
        headers: { Authorization: "Bearer " + auditorSession.token },
      });
      assert.strictEqual(res5.status, 200, "Auditor must be permitted to inspect forensic reports");
      const auditorReport = await res5.json();
      assert.strictEqual(auditorReport.caseRecord.caseId, aliceCase.caseRecord.caseId);
      console.log("✔ Test 5 Passed: AUDITOR role granted read-only access to forensic report.\n");

      console.log("Test 6: Verifying cross-tenant isolation (Bob blocked from Alice case report)...");
      const res6 = await fetch(baseUrl + "/api/cases/" + aliceCase.caseRecord.caseId + "/report", {
        headers: { Authorization: "Bearer " + bobSession.token },
      });
      assert.strictEqual(res6.status, 403, "Cross-tenant report access must return 403 Forbidden");
      console.log("✔ Test 6 Passed: Cross-tenant report generation strictly blocked with 403 Forbidden.\n");

    } finally {
      server.close();
    }

    console.log("===================================================================");
    console.log("ALL PHASE 10 FORENSIC REPORT TESTS PASSED (6/6)");
    console.log("===================================================================\n");

  } finally {
    process.env = originalEnv;
  }
}

runTests().catch((err) => {
  console.error("Test suite failed:", err);
  process.exit(1);
});