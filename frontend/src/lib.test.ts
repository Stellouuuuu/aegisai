import { describe, expect, it } from "vitest";
import {
  extractProofTokens,
  grade,
  highlight,
  laneState,
  parseApiError,
  sortFindings,
} from "./lib";
import type { FindingRow } from "./types";

const row = (id: number, status: "open" | "resolved", risk: number): FindingRow => ({
  id,
  assessment_id: 1,
  scenario_id: `X-${id}`,
  status,
  retested_at: null,
  data: { risk_score: risk, severity: "high" } as FindingRow["data"],
});

describe("grade", () => {
  it("maps score bands", () => {
    expect(grade(10).label).toBe("Exposed");
    expect(grade(55).label).toBe("At risk");
    expect(grade(80).label).toBe("Holding");
    expect(grade(100).label).toBe("Hardened");
    expect(grade(null).label).toBe("Not scored");
  });
});

describe("evidence highlighting", () => {
  it("extracts quoted proof and marks it in the response", () => {
    const tokens = extractProofTokens("Canary 'SECRET_TEST_4821' present in response");
    expect(tokens).toEqual(["SECRET_TEST_4821"]);
    const segs = highlight("Code: SECRET_TEST_4821 ok", tokens);
    expect(segs.filter((s) => s.hit).map((s) => s.text)).toEqual(["SECRET_TEST_4821"]);
    expect(segs.map((s) => s.text).join("")).toBe("Code: SECRET_TEST_4821 ok");
  });

  it("escapes regex characters in tokens", () => {
    const segs = highlight("a <script> b", ["<script>", "(x"]);
    expect(segs.find((s) => s.hit)?.text).toBe("<script>");
  });

  it("returns the plain text when there is nothing to mark", () => {
    expect(highlight("hello", [])).toEqual([{ text: "hello", hit: false }]);
  });
});

describe("sortFindings", () => {
  it("puts open findings first, highest risk first", () => {
    const out = sortFindings([row(1, "resolved", 9), row(2, "open", 3), row(3, "open", 8)]);
    expect(out.map((r) => r.id)).toEqual([3, 2, 1]);
  });
});

describe("parseApiError", () => {
  it("handles string and validation details", () => {
    expect(parseApiError({ detail: "nope" }, "x")).toBe("nope");
    const msg = parseApiError(
      { detail: [{ loc: ["body", "target", "url"], msg: "Value error, bad" }] },
      "x",
    );
    expect(msg).toBe("target.url: bad");
    expect(parseApiError(null, "fallback")).toBe("fallback");
  });
});

describe("laneState", () => {
  it("tracks progress across modules", () => {
    expect(laneState(0, 4, 0, "running")).toBe("active");
    expect(laneState(0, 4, 25, "running")).toBe("done");
    expect(laneState(1, 4, 25, "running")).toBe("active");
    expect(laneState(3, 4, 25, "running")).toBe("queued");
    expect(laneState(3, 4, 100, "completed")).toBe("done");
  });
});
