import { Canvas, useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";

// One persistent scene; the camera travels with page scroll (0..1):
// globe -> server corridor -> inspected site -> threat network -> shield.
const C = { blue: "#1769D2", cyan: "#38BDF8", navy: "#071426" };

function useScroll() {
  const p = useRef(0);
  useFrame(() => {
    const max = document.documentElement.scrollHeight - window.innerHeight;
    const t = max > 0 ? window.scrollY / max : 0;
    p.current += (t - p.current) * 0.08;
  });
  return p;
}

function Globe() {
  const g = useRef<THREE.Group>(null);
  const pts = useMemo(() => {
    const a: number[] = [];
    for (let i = 0; i < 1600; i++) {
      const y = 1 - (i / 1599) * 2, r = Math.sqrt(1 - y * y), th = i * 2.39996;
      a.push(Math.cos(th) * r * 2, y * 2, Math.sin(th) * r * 2);
    }
    return new Float32Array(a);
  }, []);
  useFrame((_, d) => { if (g.current) g.current.rotation.y += Math.min(d, 0.05) * 0.12; });
  return (
    <group ref={g}>
      <mesh><sphereGeometry args={[1.96, 48, 48]} /><meshStandardMaterial color={C.navy} emissive={C.blue} emissiveIntensity={0.15} roughness={0.6} /></mesh>
      <mesh><sphereGeometry args={[2.02, 24, 16]} /><meshBasicMaterial color={C.blue} wireframe transparent opacity={0.18} /></mesh>
      <points><bufferGeometry><bufferAttribute attach="attributes-position" args={[pts, 3]} /></bufferGeometry><pointsMaterial color={C.cyan} size={0.025} /></points>
    </group>
  );
}

function Corridor() {
  const racks = useMemo(() => Array.from({ length: 24 }, (_, i) => i), []);
  return (
    <group position={[0, 0, -14]}>
      {racks.map((i) => [-1, 1].map((s) => (
        <group key={`${i}${s}`} position={[s * 2.2, 0, -i * 2.2]}>
          <mesh><boxGeometry args={[1, 3.2, 1.6]} /><meshStandardMaterial color="#0d2240" metalness={0.6} roughness={0.4} /></mesh>
          {[-1, -0.4, 0.2, 0.8].map((y) => (
            <mesh key={y} position={[-s * 0.51, y, 0]}><boxGeometry args={[0.02, 0.06, 1.2]} /><meshBasicMaterial color={i % 3 ? C.blue : C.cyan} /></mesh>
          ))}
        </group>
      )))}
      <mesh rotation-x={-Math.PI / 2} position={[0, -1.6, -25]}><planeGeometry args={[8, 60]} /><meshStandardMaterial color="#081a30" metalness={0.8} roughness={0.3} /></mesh>
    </group>
  );
}

function Browser() {
  const scan = useRef<THREE.Mesh>(null);
  useFrame(({ clock }) => { if (scan.current) scan.current.position.y = Math.sin(clock.elapsedTime) * 1.1; });
  return (
    <group position={[0, 0, -72]}>
      <mesh><boxGeometry args={[4.4, 2.8, 0.06]} /><meshStandardMaterial color="#0e2747" emissive={C.blue} emissiveIntensity={0.1} /></mesh>
      <mesh position={[0, 1.25, 0.04]}><boxGeometry args={[4.4, 0.3, 0.02]} /><meshBasicMaterial color={C.blue} /></mesh>
      {[0.6, 0.2, -0.2, -0.6].map((y, i) => (
        <mesh key={y} position={[-0.6 + i * 0.1, y, 0.05]}><boxGeometry args={[2.6 - i * 0.4, 0.12, 0.01]} /><meshBasicMaterial color="#29507f" /></mesh>
      ))}
      <mesh ref={scan} position={[0, 0, 0.08]}><boxGeometry args={[4.4, 0.03, 0.01]} /><meshBasicMaterial color={C.cyan} /></mesh>
    </group>
  );
}

function Network() {
  const { nodes, lines } = useMemo(() => {
    const n = Array.from({ length: 40 }, (_, i) => new THREE.Vector3(Math.sin(i * 7.1) * 4, Math.cos(i * 3.3) * 2.4, Math.sin(i * 1.7) * 3));
    const l: number[] = [];
    n.forEach((a, i) => n.forEach((b, j) => { if (j > i && a.distanceTo(b) < 2.4) l.push(a.x, a.y, a.z, b.x, b.y, b.z); }));
    return { nodes: n, lines: new Float32Array(l) };
  }, []);
  const sev = ["#ef4444", "#f59e0b", C.cyan, C.blue];
  return (
    <group position={[0, 0, -92]}>
      <lineSegments><bufferGeometry><bufferAttribute attach="attributes-position" args={[lines, 3]} /></bufferGeometry><lineBasicMaterial color={C.blue} transparent opacity={0.35} /></lineSegments>
      {nodes.map((p, i) => (
        <mesh key={i} position={p}><sphereGeometry args={[i % 9 === 0 ? 0.12 : 0.06, 12, 12]} /><meshBasicMaterial color={sev[i % 9 === 0 ? (i % 2) : 2 + (i % 2)]} /></mesh>
      ))}
    </group>
  );
}

function Shield() {
  const shape = useMemo(() => {
    const s = new THREE.Shape();
    s.moveTo(0, 1.3); s.bezierCurveTo(0.6, 1.1, 1, 1.1, 1.1, 1.0); s.lineTo(1.1, 0);
    s.bezierCurveTo(1.1, -0.8, 0.4, -1.2, 0, -1.4); s.bezierCurveTo(-0.4, -1.2, -1.1, -0.8, -1.1, 0);
    s.lineTo(-1.1, 1.0); s.bezierCurveTo(-1, 1.1, -0.6, 1.1, 0, 1.3);
    return s;
  }, []);
  const g = useRef<THREE.Group>(null);
  useFrame((_, d) => { if (g.current) g.current.rotation.y += Math.min(d, 0.05) * 0.4; });
  return (
    <group position={[0, 0, -112]}>
      <group ref={g}>
        <mesh position={[0, 0, -0.1]}><extrudeGeometry args={[shape, { depth: 0.2, bevelEnabled: true, bevelSize: 0.05, bevelThickness: 0.05 }]} /><meshStandardMaterial color={C.blue} metalness={0.7} roughness={0.25} emissive={C.blue} emissiveIntensity={0.25} /></mesh>
      </group>
      {[2, 2.6, 3.2].map((r) => (
        <mesh key={r} rotation-x={Math.PI / 2}><torusGeometry args={[r, 0.01, 8, 96]} /><meshBasicMaterial color={C.cyan} transparent opacity={0.4} /></mesh>
      ))}
    </group>
  );
}

function Particles() {
  const pos = useMemo(() => {
    const a = new Float32Array(1500 * 3);
    for (let i = 0; i < 1500; i++) { a[i * 3] = (Math.random() - 0.5) * 14; a[i * 3 + 1] = (Math.random() - 0.5) * 8; a[i * 3 + 2] = 8 - Math.random() * 125; }
    return a;
  }, []);
  return <points><bufferGeometry><bufferAttribute attach="attributes-position" args={[pos, 3]} /></bufferGeometry><pointsMaterial color={C.cyan} size={0.03} transparent opacity={0.6} /></points>;
}

// Camera keyframes [scroll, z, x]
const KEYS: [number, number, number][] = [[0, 7, -2.6], [0.18, 2.5, 0], [0.42, -60, 0], [0.6, -67, 0], [0.8, -86, 0], [1, -106, 0]];
function Rig({ reduced }: { reduced: boolean }) {
  const p = useScroll();
  useFrame(({ camera }) => {
    const t = reduced ? 0 : p.current;
    let i = 0; while (i < KEYS.length - 2 && t > KEYS[i + 1][0]) i++;
    const [t0, z0, x0] = KEYS[i], [t1, z1, x1] = KEYS[i + 1];
    const k = THREE.MathUtils.smootherstep(t, t0, t1);
    camera.position.set(THREE.MathUtils.lerp(x0, x1, k), 0, THREE.MathUtils.lerp(z0, z1, k));
    camera.lookAt(camera.position.x * 0.3, 0, camera.position.z - 10);
  });
  return null;
}

export default function SecurityScene() {
  const reduced = typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  return (
    <Canvas dpr={[1, 1.5]} camera={{ fov: 55, position: [-2.6, 0, 7] }} gl={{ antialias: true, powerPreference: "high-performance" }}
      onCreated={({ gl }) => gl.domElement.parentElement?.parentElement?.setAttribute("data-scene-ready", "1")}>
      <color attach="background" args={[C.navy]} />
      <fog attach="fog" args={[C.navy, 6, 26]} />
      <ambientLight intensity={0.5} />
      <pointLight position={[4, 3, 6]} intensity={40} color={C.cyan} />
      <directionalLight position={[-3, 4, 2]} intensity={1.2} color="#9cc7ff" />
      <Rig reduced={reduced} />
      <Globe /><Corridor /><Browser /><Network /><Shield /><Particles />
      <pointLight position={[0, 2, -40]} intensity={30} color={C.blue} distance={30} />
      <pointLight position={[0, 2, -110]} intensity={40} color={C.cyan} distance={20} />
    </Canvas>
  );
}
