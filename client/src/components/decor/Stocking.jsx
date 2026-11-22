import { C } from "./palette.js";
export default function Stocking() {
  return (
    <svg viewBox="0 0 80 110" className="stk"><path d="M20 10h40v46c0 10-6 14-16 18L28 98c-6 6-22 2-20-12 1-8 8-12 12-18z" fill={C.red} /><rect x="16" y="6" width="48" height="18" rx="5" fill={C.cream} stroke={C.kraft} strokeWidth="2" /><path d="M10 88c-2 10 10 12 18 4l8-12-12-6z" fill={C.green} /><path d="M26 34h28M26 44h28" stroke={C.cream} strokeWidth="2" strokeDasharray="3 5" strokeLinecap="round" /><circle cx="40" cy="14" r="0" /></svg>
  );
}
