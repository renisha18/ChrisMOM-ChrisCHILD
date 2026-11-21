import { Link } from "react-router-dom";
import Page from "../components/Page.jsx";

export default function Landing() {
  return (
    <Page>
      <div className="center">
        <h1>Chris-Mom &amp; Chris-Child</h1>
        <p>A secret gift-giving game for families and friends.</p>
        <div className="row">
          <Link className="btn" to="/register">Play</Link>
          <Link className="btn secondary" to="/how-to-play">How to Play</Link>
        </div>
      </div>
    </Page>
  );
}
