import { C } from "./palette.js";
export default function CandyCane() {
  return (
    <svg viewBox="0 0 70 120" className="stk"><path d="M18 114V44a22 22 0 0 1 44 0v6" fill="none" stroke={C.cream} strokeWidth="17" strokeLinecap="round" /><path d="M18 114V44a22 22 0 0 1 44 0v6" fill="none" stroke={C.red} strokeWidth="9" strokeLinecap="round" strokeDasharray="9 10" /><path d="M9 20c6-6 14-8 22-8" fill="none" stroke={C.green} strokeWidth="1.8" strokeLinecap="round" /></svg>
  );
}
