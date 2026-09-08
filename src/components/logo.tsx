import { cn } from "@/lib/utils";
import mark from "@/assets/sentrax-mark.png";

export function Logo({ className, showText = true }: { className?: string; showText?: boolean }) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <img src={mark} alt="SentraX" width={36} height={36} className="h-8 w-8 object-contain" />
      {showText && (
        <span className="text-lg font-semibold tracking-tight text-foreground">
          SentraX
        </span>
      )}
    </div>
  );
}
