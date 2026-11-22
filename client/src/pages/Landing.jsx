import { Link } from "react-router-dom";
import Page from "../components/Page.jsx";

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

/* ---------- Side decor (original inline SVG) ---------- */
const Tag = ({ color = KRAFT, ink = RED }) => (
  <svg viewBox="0 0 90 140"><path d="M45 4c-8 0-12 6-8 12" fill="none" stroke={KRAFT} strokeWidth="3" /><path d="M45 4c-30 20-34 40-8 30" fill="none" stroke={GOLD} strokeWidth="2" />
    <path d="M25 30h40l12 14v86H13V44z" fill={color} stroke={RED_D} strokeOpacity=".3" /><circle cx="45" cy="44" r="5" fill={CREAM} stroke={GOLD} strokeWidth="2" />
    <path d="M24 70h42M24 84h30" stroke={ink} strokeOpacity=".5" strokeWidth="2" strokeLinecap="round" /><text x="45" y="116" textAnchor="middle" fontFamily="Pinyon Script, cursive" fontSize="24" fill={ink}>Joy</text></svg>
);
const Ticket = ({ color = RED, text = "ADMIT ONE" }) => (
  <svg viewBox="0 0 150 76"><path d="M6 6h138v22a9 9 0 0 0 0 20v22H6V48a9 9 0 0 0 0-20z" fill={color} />
    <path d="M104 8v60" stroke={CREAM} strokeDasharray="3 4" strokeWidth="2" /><rect x="12" y="12" width="86" height="52" rx="3" fill="none" stroke={GOLD} strokeWidth="1.5" />
    <text x="55" y="42" textAnchor="middle" fontFamily="Cormorant SC, serif" fontWeight="700" fontSize="15" fill={CREAM}>{text}</text>
    <path d="M124 26l3 8h8l-6 5 2 8-7-5-7 5 2-8-6-5h8z" fill={GOLD} /></svg>
);
const Envelope = () => (
  <svg viewBox="0 0 150 120"><rect x="30" y="8" width="84" height="70" rx="3" fill={PAPER} transform="rotate(-5 72 43)" /><path d="M42 30h58M42 42h48M42 54h54" stroke={RED} strokeOpacity=".45" strokeWidth="2" strokeLinecap="round" transform="rotate(-5 72 43)" />
    <path d="M34 4v22a5 5 0 0 0 10 0V8" fill="none" stroke="#9aa0a6" strokeWidth="2.5" strokeLinecap="round" />
    <rect x="8" y="48" width="134" height="66" rx="6" fill={RED} /><path d="M8 54l67 40 67-40" fill="none" stroke={RED_D} strokeWidth="3" /><path d="M8 112l50-38M142 112l-50-38" stroke={RED_D} strokeWidth="2" />
    <circle cx="75" cy="94" r="9" fill={GOLD} /></svg>
);
const Bow = ({ color = RED }) => (
  <svg viewBox="0 0 100 80"><path d="M50 40C30 8 4 14 8 36c3 20 30 10 42 4zM50 40C70 8 96 14 92 36c-3 20-30 10-42 4z" fill={color} />
    <path d="M50 42L28 76l12 2 10-26 10 26 12-2z" fill={color} stroke={RED_D} strokeOpacity=".4" /><rect x="42" y="30" width="16" height="20" rx="6" fill={color} stroke={RED_D} strokeOpacity=".5" /></svg>
);
const Holly = () => (
  <svg viewBox="0 0 110 80"><path d="M55 44c-8-16-30-18-46-8 10 18 30 20 46 8zM55 44c8-16 30-18 46-8-10 18-30 20-46 8z" fill={GREEN} stroke={GREEN_D} />
    <path d="M55 44L18 40M55 44l37-4" stroke={GREEN_D} strokeWidth="1.5" /><circle cx="48" cy="50" r="8" fill={RED} /><circle cx="63" cy="52" r="8" fill={RED} /><circle cx="55" cy="40" r="8" fill={RED_D} />
    <circle cx="46" cy="47" r="2.2" fill="#fff" opacity=".6" /></svg>
);
const Tree = ({ color = GREEN }) => (
  <svg viewBox="0 0 90 130"><rect x="38" y="104" width="14" height="22" fill={RED_D} /><path d="M45 6L18 46h14L8 80h20L4 112h82L62 80h20L58 46h14z" fill={color} />
    <path d="M45 6l5 10-5 3-5-3z" fill={GOLD} /><circle cx="36" cy="60" r="4" fill={GOLD} /><circle cx="56" cy="76" r="4" fill={RED} /><circle cx="40" cy="96" r="4" fill={CREAM} /><circle cx="52" cy="38" r="3.5" fill={RED} /></svg>
);
const Star = () => (
  <svg viewBox="0 0 90 90"><path d="M45 6l11 25 27 3-20 18 6 27-24-14-24 14 6-27L7 34l27-3z" fill={KRAFT} stroke="#B58A4E" strokeWidth="3" strokeLinejoin="round" />
    <path d="M45 24l5 12 13 1-10 9 3 13-11-7-11 7 3-13-10-9 13-1z" fill="none" stroke={CREAM} strokeWidth="3" strokeDasharray="1 5" strokeLinecap="round" /><circle cx="45" cy="46" r="3" fill={RED} /></svg>
);
const Flake = () => (
  <svg viewBox="0 0 60 60" fill="none" stroke={GREEN} strokeWidth="2.5" strokeLinecap="round">
    {[0, 60, 120].map((r) => <g key={r} transform={`rotate(${r} 30 30)`}><path d="M30 4v52M22 12l8 6 8-6M22 48l8-6 8 6" /></g>)}</svg>
);

// side, top%, edge offset%, width px, rotation, comp, core (kept on tablet)
const DECOR = [
  ["l", 17, 3, 86, -9, <Tag />, 1], ["l", 14, 14, 76, 12, <Star />, 0], ["l", 36, 8, 140, -7, <Ticket />, 1],
  ["l", 52, 1.5, 54, 10, <Flake />, 0], ["l", 55, 13, 84, 4, <Tree />, 1], ["l", 72, 4, 130, -5, <Envelope />, 1],
  ["l", 80, 17, 86, -12, <Bow />, 0], ["l", 90, 7, 100, 8, <Holly />, 0],
  ["r", 18, 4, 130, 7, <Envelope />, 1], ["r", 16, 17, 56, -8, <Flake />, 0], ["r", 36, 9, 84, 9, <Tag color={KRAFT} ink={GREEN} />, 1],
  ["r", 50, 2, 90, -6, <Tree color={GREEN_D} />, 0], ["r", 56, 15, 140, 6, <Ticket color={GREEN} text="NICE LIST" />, 1],
  ["r", 74, 5, 84, 11, <Star />, 0], ["r", 78, 15, 92, -8, <Bow color={GREEN} />, 1], ["r", 90, 8, 104, -6, <Holly />, 0],
];

export default function Landing() {
  return (
    <Page hero>
      <Garland />
      <div className="scene" aria-hidden="true">
        {DECOR.map(([side, top, off, w, rot, el, core], i) => (
          <span key={i} className={`dec${core ? " core" : ""}`} style={{ top: `${top}%`, [side === "l" ? "left" : "right"]: `${off}%`, width: w, transform: `rotate(${rot}deg)`, zIndex: i % 3 }}>{el}</span>
        ))}
      </div>
      <div className="center">
        <p className="tagline">a secret gift-giving game</p>
        <h1 className="title-big">
          Chris-Mom <span>&amp;</span> Chris-Child
        </h1>
        <p className="lede">Draw a name, keep a secret, and spread a little Christmas joy.</p>
        <div className="stack">
          <Link className="btn" to="/register">Play</Link>
          <Link className="btn outline" to="/how-to-play">How to Play</Link>
        </div>
      </div>
    </Page>
  );
}
