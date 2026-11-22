import { C } from "./palette.js";
export default function Snowflake() {
  return (
    <svg viewBox="0 0 80 80" className="stk line" fill="none" stroke={C.green} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">{[0, 60, 120].map((r) => (<g key={r} transform={`rotate(${r} 40 40)`}><path d="M40 6v68M30 16l10 8 10-8M30 64l10-8 10 8" /></g>))}<circle cx="40" cy="40" r="4" /></svg>
  );
}
