import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export function TableShell({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("table-shell", className)} {...props} />;
}

export function Progress({ value, className }: { value: number; className?: string }) {
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-slate-800", className)}>
      <div
        className="h-full rounded-full bg-blue-500 transition-all duration-500"
        style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
      />
    </div>
  );
}
