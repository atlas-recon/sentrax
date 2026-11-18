import { lazy, Suspense, useEffect, useState } from "react";

const SecurityScene = lazy(() => import("./security-scene"));

function hasWebGL() {
  try { const c = document.createElement("canvas"); return !!(c.getContext("webgl2") || c.getContext("webgl")); } catch { return false; }
}

// Fixed, non-interactive 3D backdrop behind the homepage; falls back to a gradient.
export function SceneBackdrop() {
  const [ok, setOk] = useState(false);
  useEffect(() => setOk(hasWebGL()), []);
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 bg-hero">
      {ok && <Suspense fallback={null}><div className="h-full w-full"><SecurityScene /></div></Suspense>}
      <div className="absolute inset-0 bg-gradient-to-b from-navy/30 via-transparent to-navy/60" />
    </div>
  );
}
