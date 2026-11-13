import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ErrorBoundary } from "./ErrorBoundary";

function ExplodingChild(): never {
  throw new Error("kaboom");
}

describe("ErrorBoundary", () => {
  it("renders a recoverable error state when a child throws", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const suppressJsdomReport = (event: ErrorEvent) => event.preventDefault();
    window.addEventListener("error", suppressJsdomReport);

    render(
      <ErrorBoundary>
        <ExplodingChild />
      </ErrorBoundary>,
    );

    expect(screen.getByRole("alert")).toHaveTextContent("kaboom");
    expect(screen.getByRole("button", { name: "Reload application" })).toBeInTheDocument();
    window.removeEventListener("error", suppressJsdomReport);
    consoleError.mockRestore();
  });
});
