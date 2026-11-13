import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ShieldAlert } from "lucide-react";
import { describe, expect, it, vi } from "vitest";

import { Button } from "./button";
import { EmptyState, ErrorState, LoadingBlock } from "./states";

describe("UI states", () => {
  it("renders an empty state with an action", () => {
    render(
      <EmptyState
        icon={ShieldAlert}
        title="No scans yet"
        description="Start a scan to see findings."
        action={<Button>New scan</Button>}
      />,
    );

    expect(screen.getByText("No scans yet")).toBeInTheDocument();
    expect(screen.getByText("Start a scan to see findings.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New scan" })).toBeInTheDocument();
  });

  it("exposes errors as alerts and retries", async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    render(<ErrorState message="Registry unavailable" onRetry={onRetry} />);

    expect(screen.getByRole("alert")).toHaveTextContent("Registry unavailable");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("announces loading labels", () => {
    render(<LoadingBlock label="Building remediation plan" />);
    expect(screen.getByText("Building remediation plan")).toBeInTheDocument();
  });
});
