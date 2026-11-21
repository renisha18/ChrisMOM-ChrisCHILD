import { Link } from "react-router-dom";
import Page from "../components/Page.jsx";

function Bauble({ color, dark, len, size }) {
  return (
    <div className="bauble" aria-hidden="true">
      <div className="string" style={{ height: len }} />
      <svg width={size} height={size + 8} viewBox="0 0 50 58">
        <rect x="19" y="0" width="12" height="8" rx="2" fill="#C9A35B" />
        <circle cx="25" cy="33" r="24" fill={color} />
        <path d="M6 33a19 19 0 0 1 38 0" fill="none" stroke={dark} strokeWidth="3" strokeDasharray="2 5" opacity=".6" />
        <ellipse cx="17" cy="23" rx="5" ry="8" fill="#fff" opacity=".35" transform="rotate(25 17 23)" />
      </svg>
    </div>
  );
}

export default function Landing() {
  return (
    <Page>
      <div className="center">
        <div className="baubles">
          <Bauble color="#A3161E" dark="#7E0F15" len={28} size={44} />
          <Bauble color="#1E4A2E" dark="#163824" len={52} size={52} />
          <Bauble color="#C9A35B" dark="#A3161E" len={20} size={40} />
        </div>
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
