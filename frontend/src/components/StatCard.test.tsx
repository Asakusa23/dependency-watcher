import { render, screen } from "@testing-library/react";
import { Shield } from "lucide-react";
import { describe, expect, it } from "vitest";

import { StatCard } from "./StatCard";

describe("StatCard", () => {
  it("renders the label, value and hint", () => {
    render(<StatCard label="Dependencies" value={42} hint="12 direct" icon={Shield} />);

    expect(screen.getByText("Dependencies")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("12 direct")).toBeInTheDocument();
  });

  it("omits the hint when none is provided", () => {
    render(<StatCard label="Findings" value="0" icon={Shield} />);

    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
  });
});
