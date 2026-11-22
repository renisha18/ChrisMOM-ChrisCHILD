import { C } from "./palette.js";
export default function StampFrame() {
  return (
    <svg viewBox="0 0 120 140" className="stk"><path d="M6 6h6a4 4 0 0 0 8 0h8a4 4 0 0 0 8 0h8a4 4 0 0 0 8 0h8a4 4 0 0 0 8 0h8a4 4 0 0 0 8 0h6v6a4 4 0 0 0 0 8v8a4 4 0 0 0 0 8v8a4 4 0 0 0 0 8v8a4 4 0 0 0 0 8v8a4 4 0 0 0 0 8v8a4 4 0 0 0 0 8v8a4 4 0 0 0 0 8v6h-6a4 4 0 0 0-8 0h-8a4 4 0 0 0-8 0h-8a4 4 0 0 0-8 0h-8a4 4 0 0 0-8 0h-8a4 4 0 0 0-8 0H6v-6a4 4 0 0 0 0-8v-8a4 4 0 0 0 0-8v-8a4 4 0 0 0 0-8v-8a4 4 0 0 0 0-8v-8a4 4 0 0 0 0-8v-8a4 4 0 0 0 0-8v-8a4 4 0 0 0 0-8z" fill={C.paper} /><rect x="20" y="20" width="80" height="88" fill={C.red} /><path d="M60 40l-20 30h12l-14 22h44L68 70h12z" fill={C.green} /><path d="M20 92h80v16H20z" fill={C.cream} /><path d="M28 124h64" stroke={C.red} strokeWidth="2" strokeLinecap="round" /><path d="M30 34l2 4 4 1-4 2-2 4-2-4-4-1 4-2zM88 52l1.5 3 3 .8-3 1.4-1.5 3-1.5-3-3-1.4 3-.8z" fill={C.gold} /></svg>
  );
}
