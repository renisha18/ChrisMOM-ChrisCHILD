import { C } from "./palette.js";
export default function GiftBox() {
  return (
    <svg viewBox="0 0 100 100" className="stk"><path d="M32 30c-14-18 6-26 18 0M68 30c14-18-6-26-18 0" fill="none" stroke={C.gold} strokeWidth="7" strokeLinecap="round" /><rect x="12" y="34" width="76" height="54" rx="4" fill={C.green} /><rect x="6" y="28" width="88" height="20" rx="4" fill={C.greenD} /><rect x="44" y="28" width="12" height="60" fill={C.red} /><circle cx="50" cy="30" r="7" fill={C.red} /><path d="M20 62h14M20 72h8M66 62h14M72 72h8" stroke={C.cream} strokeWidth="2" strokeLinecap="round" /></svg>
  );
}
