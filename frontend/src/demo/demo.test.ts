import { describe, expect, it } from "vitest";
import { demoApi, READ_ONLY } from "./api";
import { assessments, findings, projects, reports } from "./data";

describe("demo data", () => {
  it("has a completed scan for every target", () => {
    expect(projects).toHaveLength(2);
    for (const project of projects) {
      const runs = assessments.filter((a) => a.project_id === project.id);
      expect(runs).toHaveLength(1);
      expect(runs[0]!.status).toBe("completed");
    }
  });

  it("turns each report into finding rows with unique ids", () => {
    const vulnerable = findings.filter((f) => f.assessment_id === 1);
    const patched = findings.filter((f) => f.assessment_id === 2);
    expect(vulnerable).toHaveLength(14);
    expect(patched).toHaveLength(0);
    expect(new Set(findings.map((f) => f.id)).size).toBe(findings.length);
    for (const row of vulnerable) {
      expect(row.scenario_id).toBe(row.data.id);
      expect(["critical", "high", "medium", "low"]).toContain(row.data.severity);
      expect(row.data.request.length).toBeGreaterThan(0);
      expect(row.data.recommendation.length).toBeGreaterThan(0);
      expect("extra" in row.data).toBe(false);
    }
  });

  it("keeps the score of the report", () => {
    expect(assessments.find((a) => a.id === 1)!.security_score).toBe(0);
    expect(assessments.find((a) => a.id === 2)!.security_score).toBe(100);
    expect(Object.keys(reports)).toEqual(["1", "2"]);
  });
});

describe("demo api", () => {
  it("reads from the bundled reports", async () => {
    expect(await demoApi.projects()).toHaveLength(2);
    expect(await demoApi.findings(1)).toHaveLength(14);
    expect((await demoApi.assessment(2)).security_score).toBe(100);
    await expect(demoApi.assessment(99)).rejects.toThrow("not found");
  });

  it("refuses every action that would change something", async () => {
    for (const action of [demoApi.createProject, demoApi.startScan, demoApi.cancel, demoApi.retest, demoApi.profile, demoApi.register]) {
      await expect((action as () => Promise<unknown>)()).rejects.toThrow(READ_ONLY);
    }
  });
});
