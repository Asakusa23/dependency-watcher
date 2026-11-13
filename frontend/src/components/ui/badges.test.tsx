import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GradeBadge, InspectionBadge, RiskFlags, SeverityBadge } from "./badges";

describe("badges", () => {
  it("renders severity labels and falls back to UNKNOWN", () => {
    const { rerender } = render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();

    rerender(<SeverityBadge severity={null} />);
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  });

  it("presents a checked inspection as SAFE", () => {
    render(<InspectionBadge status="CHECKED" />);
    expect(screen.getByText("SAFE")).toBeInTheDocument();
    expect(screen.queryByText("CHECKED")).not.toBeInTheDocument();
  });

  it("renders the grade and a dash when unavailable", () => {
    const { rerender } = render(<GradeBadge score={91} grade="A" />);
    expect(screen.getByText("A")).toBeInTheDocument();

    rerender(<GradeBadge score={null} grade={null} />);
    expect(screen.getByText("–")).toBeInTheDocument();
  });

  it("normalizes, deduplicates and truncates risk flags", () => {
    const { rerender } = render(<RiskFlags flags={["unpinned", "unpinned", "outdated"]} />);
    expect(screen.getByText("unpinned")).toBeInTheDocument();
    expect(screen.getByText("outdated")).toBeInTheDocument();
    expect(screen.getAllByText("unpinned")).toHaveLength(1);

    rerender(<RiskFlags flags={["unpinned", "outdated", "deprecated", "registry_unavailable"]} deprecated />);
    expect(screen.getByText("deprecated")).toBeInTheDocument();
    expect(screen.queryByText("registry unavailable")).not.toBeInTheDocument();
    expect(screen.getByText("+1")).toBeInTheDocument();

    rerender(<RiskFlags flags={[]} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });
});
