import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40",
  {
    variants: {
      variant: {
        primary:
          "bg-blue-600 text-white shadow-[0_8px_24px_-12px_rgba(59,130,246,.9)] hover:bg-blue-500 active:bg-blue-700",
        secondary: "border border-border bg-elevated text-slate-200 hover:border-slate-500 hover:bg-slate-800/70",
        ghost: "text-muted hover:bg-white/5 hover:text-slate-100",
        danger: "border border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20",
        outline: "border border-blue-500/30 bg-blue-500/5 text-blue-300 hover:bg-blue-500/10",
      },
      size: {
        sm: "h-8 px-3 text-xs",
        md: "h-10 px-4",
        lg: "h-11 px-5",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />
  ),
);
Button.displayName = "Button";
