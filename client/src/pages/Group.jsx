import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
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
  const [openedName, setOpenedName] = useState(null);
  const [opening, setOpening] = useState(false);
  const [chitError, setChitError] = useState("");
  const chitsRef = useRef(null);

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

  async function openChit() {
    setOpening(true);
    setChitError("");
    try {
      const d = await api(`/groups/${id}/reveal`, { method: "POST" });
      setOpenedName(d.childName);
    } catch (err) {
      setChitError(err.message);
    } finally {
      setOpening(false);
    }
  }

  if (error) {
    return (
      <Page title="Group" back="/dashboard">
        <p className="error" role="alert">{error}</p>
      </Page>
    );
  }
  if (!data) {
    return (
      <Page title="Group" back="/dashboard">
        <p>Loading...</p>
      </Page>
    );
  }

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
    <Page title={group.name} back="/dashboard" wide>
      {group.description && <p>{group.description}</p>}

      <button
        type="button"
        disabled={!group.drawn}
        onClick={() => chitsRef.current?.scrollIntoView({ behavior: "smooth", block: "center" })}
      >
        Find your Chris-Child
      </button>
      <p className="muted">{group.drawn ? "Names have been drawn." : "Available once the admin draws names."}</p>

      <div className="group-layout">
        <div className="group-main">
          <section className="panel" ref={chitsRef}>
            <h2>Chits</h2>
            {!group.drawn && <p className="muted">Chits appear once the admin draws names.</p>}
            {group.drawn && (data.revealed || openedName) && (
              <motion.div
                className="chit opened"
                initial={{ rotateY: 90, opacity: 0 }}
                animate={{ rotateY: 0, opacity: 1 }}
                transition={{ duration: 0.4 }}
              >
                <p className="muted">Your Chris-Child is</p>
                <p className="chit-name">{openedName ?? data.childName}</p>
                <p className="muted">Keep it secret!</p>
              </motion.div>
            )}
            {group.drawn && !data.revealed && !openedName && (
              <>
                <p>Pick any chit to open yours.</p>
                <div className="chits">
                  {members.map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      className="chit"
                      onClick={openChit}
                      disabled={opening}
                      aria-label="Open a chit"
                    >
                      ?
                    </button>
                  ))}
                </div>
              </>
            )}
            {chitError && <p className="error" role="alert">{chitError}</p>}
          </section>

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
        </div>

        <aside className="group-side">
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
        </aside>
      </div>
    </Page>
  );
}
