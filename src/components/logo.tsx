import { cn } from "@/lib/utils";
import mark from "@/assets/shahin-mark.png";

export function Logo({ className, showText = true }: { className?: string; showText?: boolean }) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <img src={mark} alt="Shahin Security" width={36} height={36} className="h-9 w-9 object-contain" />
      {showText && (
        <span className="flex flex-col leading-none">
          <span className="text-base font-bold tracking-[0.12em] text-foreground">SHAHIN</span>
          <span className="mt-1 text-[9px] font-semibold tracking-[0.42em] text-primary">SECURITY</span>
        </span>
      )}
    </div>
  );
}
