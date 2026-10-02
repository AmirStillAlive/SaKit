import * as React from "react";
import { cn } from "../../lib/utils";

type Variant = "default" | "secondary" | "outline" | "success" | "warning" | "brand" | "destructive";

const variants: Record<Variant, string> = {
  default: "text-foreground bg-secondary/80 border border-border/40",
  secondary: "text-muted-foreground bg-muted/60 border border-border/30",
  outline: "text-foreground/80 border border-border/70 bg-transparent",
  success: "text-success bg-success/10 border border-success/25",
  warning: "text-warning bg-warning/10 border border-warning/25",
  brand: "text-brand bg-brand/10 border border-brand/25",
  destructive: "text-destructive bg-destructive/10 border border-destructive/25",
};

export function Badge({
  className,
  variant = "default",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { variant?: Variant }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium leading-5 whitespace-nowrap transition-colors",
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}
