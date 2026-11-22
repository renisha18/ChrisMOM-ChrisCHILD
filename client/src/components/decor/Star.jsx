import { C } from "./palette.js";
export default function Star() {
  return (
    <svg viewBox="0 0 100 100" className="stk"><path d="M50 6l14 29 32 4-23 22 6 32-29-16-29 16 6-32L4 39l32-4z" fill={C.gold} strokeLinejoin="round" /><path d="M50 26l7 15 16 2-12 11 3 16-14-8-14 8 3-16-12-11 16-2z" fill="none" stroke={C.cream} strokeWidth="2.2" strokeLinejoin="round" /></svg>
  );
}
