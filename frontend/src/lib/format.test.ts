import { describe, expect, it } from "vitest";

import {
  formatDuration,
  formatNumber,
  percent,
  pluralize,
  scoreColor,
  scoreLabel,
  titleCase,
} from "./format";

describe("format helpers", () => {
  it("formats durations without hiding sub-second scans", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(0.2)).toBe("<1s");
    expect(formatDuration(4.25)).toBe("4.3s");
    expect(formatDuration(125)).toBe("2m 5s");
  });

  it("formats percentages and numbers", () => {
    expect(percent(85.67)).toBe("85.7%");
    expect(percent(null)).toBe("0.0%");
    expect(formatNumber(1234567)).not.toBe("0");
  });

  it("maps scores to labels and colors", () => {
    expect(scoreLabel(null)).toBe("Not evaluated");
    expect(scoreLabel(95)).toBe("Strong");
    expect(scoreLabel(78)).toBe("Good");
    expect(scoreLabel(68)).toBe("Needs attention");
    expect(scoreLabel(45)).toBe("At risk");
    expect(scoreLabel(10)).toBe("Critical exposure");
    expect(scoreColor(null)).toBe("#7f90a8");
    expect(scoreColor(95)).toBe("#22c55e");
    expect(scoreColor(10)).toBe("#ef4444");
  });

  it("normalizes labels and plurals", () => {
    expect(titleCase("inspection_status")).toBe("Inspection Status");
    expect(pluralize(1, "dependency")).toBe("dependency");
    expect(pluralize(2, "dependency")).toBe("dependencies");
    expect(pluralize(2, "scan")).toBe("scans");
  });
});
