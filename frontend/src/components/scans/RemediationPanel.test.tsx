import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import type { Remediation } from "@/types";
import { RemediationPanel } from "./RemediationPanel";

vi.mock("@/lib/api", () => ({
  api: { remediation: vi.fn() },
}));

const remediationMock = vi.mocked(api.remediation);

function makeRemediation(overrides: Partial<Remediation> = {}): Remediation {
  return {
    scan_id: "scan-12345678",
    generated_at: "2026-11-13T10:00:05Z",
    summary: {
      urgent_upgrades: 1,
      total_recommendations: 1,
      unfixable: 0,
      maintenance_updates: 1,
      multi_version_packages: {},
    },
    recommendations: [
      {
        dependency_id: 7,
        package: "urllib3",
        ecosystem: "PyPI",
        current_version: "1.26.5",
        recommended_version: "2.2.2",
        direct: true,
        severity: "HIGH",
        priority_level: "HIGH",
        priority_score: 88,
        advisories: ["GHSA-34jh-p97f-mpxf"],
        reasons: ["Direct runtime dependency", "Fixed release available"],
        conflicts: ["Requires requests>=2.31"],
        breaking_risk: "major",
        action: "upgrade",
      },
    ],
    maintenance_updates: [
      {
        dependency_id: 9,
        package: "requests",
        ecosystem: "PyPI",
        current_version: "2.28.0",
        latest_version: "2.32.3",
        direct: true,
        breaking_risk: "low",
      },
    ],
    notice: "Recommendations are heuristic and must be reviewed before upgrading.",
    ...overrides,
  };
}

describe("RemediationPanel", () => {
  beforeEach(() => {
    remediationMock.mockReset();
  });

  it("renders recommendations, conflicts and maintenance updates", async () => {
    remediationMock.mockResolvedValue(makeRemediation());

    render(<RemediationPanel scanId="scan-12345678" />);

    expect(await screen.findByText("urllib3")).toBeInTheDocument();
    expect(screen.getByText("1.26.5")).toBeInTheDocument();
    expect(screen.getByText("2.2.2")).toBeInTheDocument();
    expect(screen.getByText("P88")).toBeInTheDocument();
    expect(screen.getByText("major risk")).toBeInTheDocument();
    expect(screen.getByText("Requires requests>=2.31")).toBeInTheDocument();
    expect(screen.getByText("requests")).toBeInTheDocument();
    expect(screen.getByText("2.32.3")).toBeInTheDocument();
    expect(screen.getByText("Recommendations are heuristic and must be reviewed before upgrading.")).toBeInTheDocument();
    expect(remediationMock).toHaveBeenCalledWith("scan-12345678");
  });

  it("shows the empty advisory state when nothing needs upgrading", async () => {
    remediationMock.mockResolvedValue(
      makeRemediation({
        summary: {
          urgent_upgrades: 0,
          total_recommendations: 0,
          unfixable: 0,
          maintenance_updates: 0,
          multi_version_packages: {},
        },
        recommendations: [],
        maintenance_updates: [],
      }),
    );

    render(<RemediationPanel scanId="scan-12345678" />);

    expect(await screen.findByText("No advisory-driven upgrades")).toBeInTheDocument();
  });

  it("surfaces request errors with a retry action", async () => {
    remediationMock.mockRejectedValueOnce(new Error("Remediation service unavailable"));

    render(<RemediationPanel scanId="scan-12345678" />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Remediation service unavailable");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("does not request data while disabled", () => {
    render(<RemediationPanel scanId="scan-12345678" enabled={false} />);

    expect(screen.getByText("Remediation is available when the scan completes.")).toBeInTheDocument();
    expect(remediationMock).not.toHaveBeenCalled();
  });
});
