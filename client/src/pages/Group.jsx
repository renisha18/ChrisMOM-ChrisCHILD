import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api.js";
import Page from "../components/Page.jsx";

export default function Group() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [showMembers, setShowMembers] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setData(null);
    setError("");
    api(`/groups/${id}`)
      .then(setData)
      .catch((err) => setError(err.message));
  }, [id]);

  if (error) {
    return (
      <Page title="Group" back="/dashboard">
        <p className="error" role="alert">{error}</p>
      </Page>
    );
  }
  if (!data) return <p className="center">Loading...</p>;

  const { group, members } = data;
  const inviteLink = group.inviteCode ? `${window.location.origin}/join/${group.inviteCode}` : "";
  const waHref = `https://wa.me/?text=${encodeURIComponent(
    `Join our Chris-Mom & Chris-Child group "${group.name}": ${inviteLink}`
  )}`;

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(inviteLink);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable; the link is visible to copy manually */
    }
  }

  return (
    <Page title={group.name} back="/dashboard">
      {group.description && <p>{group.description}</p>}

      <button type="button" disabled>Find your Chris-Child</button>
      <p className="muted">{group.drawn ? "Names have been drawn." : "Available once the admin draws names."}</p>

      <button type="button" className="secondary" onClick={() => setShowMembers((s) => !s)}>
        {showMembers ? "Hide members" : `Show members (${members.length})`}
      </button>
      {showMembers && (
        <section className="panel">
          <h2>Members ({members.length})</h2>
          <ul className="list">
            {members.map((m) => (
              <li key={m.id}>
                {m.displayName}{m.isMe ? " (you)" : ""}
                <span className="muted"> · {m.joined ? "joined" : "not joined"}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {group.isAdmin && (
        <section className="panel">
          <h2>Invite</h2>
          <input readOnly value={inviteLink} onFocus={(e) => e.target.select()} aria-label="Invite link" />
          <div className="row left">
            <button type="button" className="secondary" onClick={copyLink}>{copied ? "Copied!" : "Copy link"}</button>
            <a className="btn" href={waHref} target="_blank" rel="noreferrer">Share on WhatsApp</a>
          </div>
        </section>
      )}
    </Page>
  );
}
