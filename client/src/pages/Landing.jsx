import { useEffect } from "react";
import { Link } from "react-router-dom";
import Page from "../components/Page.jsx";
import { Bauble as BaubleSticker, CandyCane, GiftBox, Star, ChristmasTree, Stocking, CocoaMug, WrappedCandy, Holly, Snowflake, StampFrame } from "../components/decor/index.js";

const GOLD = "#C9A35B", RED = "#A3161E", RED_D = "#7E0F15", GREEN = "#1E4A2E", GREEN_D = "#163824", CREAM = "#FBF4E6", KRAFT = "#D9C7A7", PAPER = "#F3E7D3";

/* ---------- Garland: 4 swags across full width, baubles hang from the curve ---------- */
const SWAGS = 4, G_H = 64, DIP = 64; // quadratic control point y; curve ends at y=8
const curveY = (u) => {
  const s = Math.min(SWAGS - 1, Math.floor(u * SWAGS));
  const t = u * SWAGS - s;
  return 8 * (1 - t) ** 2 + 2 * DIP * (1 - t) * t + 8 * t ** 2;
};
const BAUBLES = [
  [4, 30, 38, RED], [10, 62, 54, GREEN], [16, 24, 34, CREAM], [22, 78, 46, GOLD],
  [29, 40, 58, RED], [35, 26, 36, GREEN], [41, 70, 44, CREAM], [47, 34, 52, GOLD],
  [53, 58, 40, RED], [59, 28, 56, GREEN], [65, 74, 36, GOLD], [71, 36, 48, CREAM],
  [77, 66, 56, RED], [83, 24, 34, GOLD], [89, 52, 46, GREEN], [95, 32, 40, RED],
];
const shade = { [RED]: RED_D, [GREEN]: GREEN_D, [GOLD]: RED, [CREAM]: KRAFT };

function Garland() {
  const d = Array.from({ length: SWAGS }, (_, i) => {
    const x0 = (1000 / SWAGS) * i, x1 = x0 + 1000 / SWAGS;
    return `${i ? "" : `M${x0} 8 `}Q${(x0 + x1) / 2} ${DIP} ${x1} 8`;
  }).join(" ");
  return (
    <div className="garland" aria-hidden="true">
      <svg className="garland-line" viewBox={`0 0 1000 ${G_H}`} preserveAspectRatio="none">
        <path d={d} fill="none" stroke={GREEN} strokeWidth="9" vectorEffect="non-scaling-stroke" strokeLinecap="round" />
        <path d={d} fill="none" stroke={CREAM} strokeOpacity=".35" strokeWidth="3" strokeDasharray="2 7" vectorEffect="non-scaling-stroke" />
        <path d={d} fill="none" stroke={GOLD} strokeWidth="1.5" strokeDasharray="1 14" vectorEffect="non-scaling-stroke" />
      </svg>
      {BAUBLES.map(([x, len, size, color], i) => (
        <div key={i} className={`bauble${i % 3 === 1 ? " b-mid" : ""}${i % 2 ? " b-alt" : ""}`}
          style={{ left: `${x}%`, top: curveY(x / 100), animationDelay: `${-(i * 0.7) % 5}s`, animationDuration: `${3.6 + (i % 4) * 0.5}s` }}>
          <div className="string" style={{ height: len }} />
          <svg width={size} height={size + 8} viewBox="0 0 50 58">
            <rect x="19" y="0" width="12" height="8" rx="2" fill={GOLD} />
            <circle cx="25" cy="33" r="24" fill={color} />
            <path d="M6 33a19 19 0 0 1 38 0" fill="none" stroke={shade[color]} strokeWidth="3" strokeDasharray="2 5" opacity=".6" />
            <ellipse cx="17" cy="23" rx="5" ry="8" fill="#fff" opacity=".4" transform="rotate(25 17 23)" />
          </svg>
        </div>
      ))}
    </div>
  );
}

/* ---------- Sticker scatter (>=1100px, side gutters only): [Component, side, f 0..1 across gutter, top%, width px, rotation] ---------- */
const S = [
  [ChristmasTree, "l", 0.07, 20, 120, -6], [GiftBox, "l", 0.47, 30, 96, 8], [Stocking, "l", 0.17, 52, 84, -10], [CocoaMug, "l", 0.5, 56, 100, 6],
  [StampFrame, "l", 0.1, 72, 100, 5], [CandyCane, "l", 0.57, 76, 64, -14], [Holly, "l", 0.27, 90, 90, 8], [Star, "l", 0.73, 16, 64, 14], [Snowflake, "l", 0.8, 44, 52, 0],
  [CandyCane, "r", 0.33, 22, 64, 12], [BaubleSticker, "r", 0.67, 17, 70, -8], [StampFrame, "r", 0.43, 34, 104, -6], [Star, "r", 0.87, 50, 62, -12],
  [GiftBox, "r", 0.33, 58, 100, -8], [ChristmasTree, "r", 0.7, 66, 112, 6], [WrappedCandy, "r", 0.43, 80, 110, 10], [Snowflake, "r", 0.87, 34, 50, 0], [Holly, "r", 0.7, 90, 88, -8],
];
/* <1100px: small centered rows above the tagline / below the buttons: [Component, width px, rotation] */
const ROW_TOP = [[ChristmasTree, 56, -6], [GiftBox, 56, 6], [BaubleSticker, 48, -4]];
const ROW_BOTTOM = [[CocoaMug, 56, 4], [CandyCane, 40, -10], [WrappedCandy, 64, 8]];

const DecoRow = ({ items, below }) => (
  <div className={`deco-row${below ? " below" : ""}`} aria-hidden="true">
    {items.map(([Comp, w, rot], i) => (
      <span key={i} className="deco-item" style={{ "--w": `${w}px`, "--r": `${rot}deg` }}><Comp /></span>
    ))}
  </div>
);

export default function Landing() {
  // Dev-only guard: warn if any visible scattered decor intersects the title block.
  useEffect(() => {
    if (!import.meta.env.DEV) return undefined;
    const check = () => {
      const c = document.querySelector(".page.hero > .center")?.getBoundingClientRect();
      if (!c) return;
      document.querySelectorAll(".dec").forEach((el) => {
        const r = el.getBoundingClientRect();
        if (!r.width || !r.height) return; // hidden
        if (r.left < c.right && r.right > c.left && r.top < c.bottom && r.bottom > c.top) {
          console.warn("[Landing] decor overlaps .center at", window.innerWidth + "px:", el);
        }
      });
    };
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  return (
    <Page hero>
      <svg width="0" height="0" style={{ position: "absolute" }} aria-hidden="true" focusable="false">
        <filter id="grain" x="0" y="0" width="100%" height="100%">
          <feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="2" seed="4" result="n" />
          <feColorMatrix in="n" type="matrix" values="0 0 0 0 .23  0 0 0 0 .16  0 0 0 0 .12  0 0 0 -1.1 .75" result="g" />
          <feComposite in="g" in2="SourceAlpha" operator="in" result="gi" />
          <feBlend in="SourceGraphic" in2="gi" mode="multiply" />
        </filter>
      </svg>
      <Garland />
      <div className="scene" aria-hidden="true">
        {S.map(([Comp, side, f, y, w, rot], i) => (
          <span key={i} className={`dec side-${side}`} style={{ top: `${y}%`, "--w": `${w}px`, "--f": f, "--r": `${rot}deg`, zIndex: i % 3 }}>
            <Comp />
          </span>
        ))}
      </div>
      <div className="center">
        <DecoRow items={ROW_TOP} />
        <p className="tagline">a secret gift-giving game</p>
        <h1 className="title-big">
          Chris-Mom <span>&amp;</span> Chris-Child
        </h1>
        <p className="lede">Draw a name, keep a secret, and spread a little Christmas joy.</p>
        <div className="stack">
          <Link className="btn" to="/register">Play</Link>
          <Link className="btn outline" to="/how-to-play">How to Play</Link>
        </div>
        <DecoRow items={ROW_BOTTOM} below />
      </div>
    </Page>
  );
}
