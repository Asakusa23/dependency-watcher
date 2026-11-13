import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import type { ScanSummary } from "@/types";
import { ScanTable } from "./ScanTable";

function makeScan(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    id: "scan-12345678",
    project_name: "demo-app",
    source_type: "local",
    source_reference: "/srv/demo-app",
    status: "completed",
    phase: "completed",
    progress: 100,
    created_at: "2026-11-13T10:00:00Z",
    started_at: "2026-11-13T10:00:01Z",
    completed_at: "2026-11-13T10:00:05Z",
    duration_seconds: 4.2,
    security_score: 82,
    score_grade: "B",
    score_breakdown: null,
    coverage_percent: 100,
    total_dependencies: 12,
    direct_dependencies: 5,
    transitive_dependencies: 7,
    checked_dependencies: 12,
    unknown_dependencies: 0,
    vulnerable_dependencies: 1,
    vulnerability_count: 2,
    critical_count: 1,
    high_count: 1,
    medium_count: 0,
    low_count: 0,
    info_count: 0,
    outdated_count: 3,
    unpinned_count: 1,
    deprecated_count: 0,
    ecosystems: ["PyPI", "npm"],
    error_message: null,
    ...overrides,
  };
}

function renderTable(scans: ScanSummary[], onDelete?: (id: string) => Promise<void>) {
  return render(
    <MemoryRouter initialEntries={["/scans"]}>
      <Routes>
        <Route path="/scans" element={<ScanTable scans={scans} onDelete={onDelete} />} />
        <Route path="/scans/:id" element={<div>Scan detail page</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ScanTable", () => {
  it("renders scan metadata and findings", () => {
    renderTable([makeScan()]);

    expect(screen.getByText("demo-app")).toBeInTheDocument();
    expect(screen.getByText("PyPI, npm")).toBeInTheDocument();
    expect(screen.getByText("completed")).toBeInTheDocument();
    expect(screen.getByText("B")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("2 hot")).toBeInTheDocument();
  });

  it("navigates to the scan detail page when a row is clicked", async () => {
    const user = userEvent.setup();
    renderTable([makeScan()]);

    await user.click(screen.getByText("demo-app"));
    expect(await screen.findByText("Scan detail page")).toBeInTheDocument();
  });

  it("asks for confirmation and deletes a scan", async () => {
    const user = userEvent.setup();
    const onDelete = vi.fn().mockResolvedValue(undefined);
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    renderTable([makeScan()], onDelete);

    await user.click(screen.getByRole("button", { name: "Delete scan demo-app" }));

    expect(confirm).toHaveBeenCalledWith('Delete the scan for “demo-app”? Historical results will be removed.');
    await waitFor(() => expect(onDelete).toHaveBeenCalledWith("scan-12345678"));
    confirm.mockRestore();
  });

  it("does not delete when confirmation is cancelled", async () => {
    const user = userEvent.setup();
    const onDelete = vi.fn().mockResolvedValue(undefined);
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    renderTable([makeScan()], onDelete);

    await user.click(screen.getByRole("button", { name: "Delete scan demo-app" }));

    expect(confirm).toHaveBeenCalled();
    expect(onDelete).not.toHaveBeenCalled();
    confirm.mockRestore();
  });
});
