import { cn } from "@/lib/utils";
import sentraxAsset from "@/assets/sentrax-logo.png.asset.json";

export function Logo({ className, showText = true }: { className?: string; showText?: boolean }) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <img
        src={sentraxAsset.url}
        alt="SentraX"
        className="h-9 w-9 rounded-lg object-contain shadow-glow"
      />
      {showText && (
        <span className="text-lg font-bold tracking-tight">
          Sentra<span className="text-gradient">X</span>
        </span>
      )}
    </div>
  );
}
