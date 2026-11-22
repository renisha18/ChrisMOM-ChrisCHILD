import { C } from "./palette.js";
export default function Bauble() {
  return (
    <svg viewBox="0 0 80 100" className="stk"><path d="M40 6v10" stroke={C.gold} strokeWidth="3" /><rect x="32" y="14" width="16" height="10" rx="2" fill={C.gold} /><circle cx="40" cy="62" r="32" fill={C.red} /><path d="M10 56c20 10 40 10 60 0" fill="none" stroke={C.cream} strokeWidth="5" /><path d="M12 70c18 10 38 10 56 0" fill="none" stroke={C.gold} strokeWidth="2.5" strokeDasharray="1 6" strokeLinecap="round" /><ellipse cx="27" cy="46" rx="5" ry="9" fill={C.cream} opacity=".55" transform="rotate(25 27 46)" /></svg>
  );
}
