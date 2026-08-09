import { useEffect, useState } from "react";

/** True when the app runs inside the SentraX Linux desktop build. */
export function isDesktopRuntime(): boolean {
  if (typeof navigator === "undefined") return false;
  return /SentraX-Desktop/i.test(navigator.userAgent);
}

export type DetectedOS = "athena" | "linux" | "android" | "windows" | "mac" | "other";

export function detectOS(ua: string): DetectedOS {
  const s = ua.toLowerCase();
  if (s.includes("athena")) return "athena";
  if (s.includes("android")) return "android";
  if (s.includes("linux") || s.includes("x11")) return "linux";
  if (s.includes("windows")) return "windows";
  if (s.includes("mac os") || s.includes("iphone") || s.includes("ipad")) return "mac";
  return "other";
}

/** Linux-family desktop (Athena OS, Kali, Parrot, Arch, Debian…) — Android excluded. */
export function isLinuxDesktop(os: DetectedOS) {
  return os === "linux" || os === "athena";
}

/** Hydration-safe desktop flag. */
export function useIsDesktopApp() {
  const [desktop, setDesktop] = useState(false);
  useEffect(() => setDesktop(isDesktopRuntime()), []);
  return desktop;
}

/** Hydration-safe OS detection. */
export function useDetectedOS() {
  const [os, setOS] = useState<DetectedOS | null>(null);
  useEffect(() => setOS(detectOS(navigator.userAgent)), []);
  return os;
}
