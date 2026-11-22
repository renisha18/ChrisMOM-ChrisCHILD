import { C } from "./palette.js";
export default function WrappedCandy() {
  return (
    <svg viewBox="0 0 120 70" className="stk"><path d="M34 35L4 12v46zM86 35l30-23v46z" fill={C.green} /><path d="M4 12l30 23M4 58l30-23M116 12L86 35M116 58L86 35" stroke={C.cream} strokeWidth="1.8" /><ellipse cx="60" cy="35" rx="30" ry="22" fill={C.red} /><path d="M40 24c12 8 28 8 40 0" fill="none" stroke={C.cream} strokeWidth="3" strokeLinecap="round" /><path d="M40 46c12-8 28-8 40 0" fill="none" stroke={C.gold} strokeWidth="2.2" strokeLinecap="round" /></svg>
  );
}
