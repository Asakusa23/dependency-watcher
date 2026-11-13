import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/states";

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled UI error", error, info);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="p-8">
        <ErrorState message={this.state.error.message || "The interface encountered an unexpected error."} />
        <Button className="mt-4" onClick={() => window.location.reload()}>
          Reload application
        </Button>
      </div>
    );
  }
}
