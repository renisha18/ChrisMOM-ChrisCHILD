import { C } from "./palette.js";
export default function CocoaMug() {
  return (
    <svg viewBox="0 0 110 110" className="stk"><path d="M36 22c-8-8 6-12 0-20M52 24c-8-8 6-12 0-22M68 22c-8-8 6-12 0-20" fill="none" stroke={C.red} strokeWidth="2.2" strokeLinecap="round" /><path d="M78 46h10a14 14 0 0 1 0 28H76" fill="none" stroke={C.red} strokeWidth="8" /><path d="M16 36h66v34a24 24 0 0 1-24 24H40a24 24 0 0 1-24-24z" fill={C.red} /><ellipse cx="49" cy="36" rx="33" ry="8" fill={C.paper} /><ellipse cx="49" cy="37" rx="27" ry="5" fill={C.ink} /><circle cx="38" cy="36" r="3" fill={C.cream} /><circle cx="52" cy="38" r="3" fill={C.cream} /><path d="M28 62c8 8 14-6 22 0s14-6 22 0" fill="none" stroke={C.cream} strokeWidth="2.4" strokeLinecap="round" /></svg>
  );
}
