import { C } from "./palette.js";
export default function ChristmasTree() {
  return (
    <svg viewBox="0 0 110 140" className="stk"><rect x="46" y="112" width="18" height="24" rx="2" fill={C.ink} /><path d="M55 8L22 52h16L12 88h20L6 120h98L78 88h20L72 52h16z" fill={C.green} /><path d="M26 70c14 8 44 8 58 0M20 100c20 10 50 10 70 0M38 44c10 5 24 5 34 0" fill="none" stroke={C.gold} strokeWidth="2.2" strokeLinecap="round" /><circle cx="40" cy="80" r="5" fill={C.red} /><circle cx="70" cy="62" r="5" fill={C.red} /><circle cx="58" cy="104" r="5" fill={C.red} /><path d="M55 0l4 9h9l-7 6 3 9-9-6-9 6 3-9-7-6h9z" fill={C.gold} /></svg>
  );
}
