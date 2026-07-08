import { ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

export function Logo({ className, showText = true }: { className?: string; showText?: boolean }) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="relative grid h-8 w-8 place-items-center rounded-lg bg-gradient-primary shadow-glow">
        <ShieldCheck className="h-5 w-5 text-primary-foreground" />
      </div>
      {showText && (
        <span className="text-lg font-bold tracking-tight">
          Sentra<span className="text-gradient">X</span>
        </span>
      )}
    </div>
  );
}
