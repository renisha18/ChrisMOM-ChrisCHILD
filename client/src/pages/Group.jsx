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

  const [actionError, setActionError] = useState("");
  const [drawing, setDrawing] = useState(false);
  const [chitNote, setChitNote] = useState(false);

  function load() {
    return api(`/groups/${id}`)
      .then(setData)
      .catch((err) => setError(err.message));
  }

  useEffect(() => {
    setData(null);
    setError("");
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  async function handleDraw() {
    if (!window.confirm("Send Chris-Child to everyone? This can't be undone, and members will be locked.")) return;
    setDrawing(true);
    setActionError("");
    try {
      await api(`/groups/${id}/draw`, { method: "POST" });
      await load();
    } catch (err) {
      setActionError(err.message);
    } finally {
      setDrawing(false);
    }
  }

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

      <button type="button" disabled={!group.drawn} onClick={() => setChitNote(true)}>
        Find your Chris-Child
      </button>
      <p className="muted">{group.drawn ? "Names have been drawn." : "Available once the admin draws names."}</p>
      {chitNote && <p className="muted">Chits are coming in the next update.</p>}

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

      {group.isAdmin && (
        <section className="panel">
          <h2>Send Chris-Child</h2>
          {group.drawn ? (
            <p>Already drawn. Members are locked.</p>
          ) : (
            <>
              <button type="button" onClick={handleDraw} disabled={drawing || members.length < 3}>
                {drawing ? "Sending..." : "Send Chris-Child"}
              </button>
              {members.length < 3 && <p className="muted">You need at least 3 members.</p>}
            </>
          )}
          {actionError && <p className="error" role="alert">{actionError}</p>}
        </section>
      )}
    </Page>
  );
}
