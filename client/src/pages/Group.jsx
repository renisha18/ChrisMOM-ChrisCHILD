import { useEffect, useRef, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { useParams } from "react-router-dom";
import { api } from "../api.js";
import Page from "../components/Page.jsx";
import Modal from "../components/Modal.jsx";

// Chits shuffle on their own when they appear, then settle so one can be tapped.
function ShuffleChits({ members, onPick, disabled }) {
  const reduce = useReducedMotion();
  const [order, setOrder] = useState(members.map((m) => m.id));
  const [shuffling, setShuffling] = useState(!reduce);

  useEffect(() => {
    if (reduce) return undefined;
    let n = 0;
    const t = setInterval(() => {
      n += 1;
      setOrder((o) => {
        const a = [...o];
        for (let i = a.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [a[i], a[j]] = [a[j], a[i]];
        }
        return a;
      });
      if (n >= 6) {
        clearInterval(t);
        setShuffling(false);
      }
    }, 450);
    return () => clearInterval(t);
  }, [reduce]);

  return (
    <>
      <p>{shuffling ? "Shuffling the chits..." : "Pick any chit to open yours."}</p>
      <div className="chits">
        {order.map((id) => (
          <motion.button
            key={id}
            layout={!reduce}
            transition={{ type: "spring", stiffness: 260, damping: 22 }}
            type="button"
            className="chit"
            onClick={onPick}
            disabled={disabled || shuffling}
            aria-label="Open a chit"
          >
            <span className="twine-v" aria-hidden="true" />
            <span className="twine-h" aria-hidden="true" />
            <span className="bow" aria-hidden="true">&#10086;</span>
          </motion.button>
        ))}
      </div>
    </>
  );
}

export default function Group() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [showMembers, setShowMembers] = useState(false);
  const [confirmDraw, setConfirmDraw] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", daresEnabled: false });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const anchorRef = useRef(null);
  const [copied, setCopied] = useState(false);

  const [actionError, setActionError] = useState("");
  const [drawing, setDrawing] = useState(false);
  const [openedName, setOpenedName] = useState(null);
  const [opening, setOpening] = useState(false);
  const [chitError, setChitError] = useState("");

  const [dares, setDares] = useState(null); // { sent, received }
  const [daresError, setDaresError] = useState("");
  const [showDare, setShowDare] = useState(false);
  const [confirmDare, setConfirmDare] = useState(false);
  const [dareText, setDareText] = useState("");
  const [dareSending, setDareSending] = useState(false);
  const [dareError, setDareError] = useState("");
  const [toast, setToast] = useState("");

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

  const daresOn = !!(data?.group.daresEnabled && data?.group.drawn);

  function loadDares() {
    return api(`/groups/${id}/dares`)
      .then((d) => { setDares(d); setDaresError(""); })
      .catch((err) => setDaresError(err.message));
  }

  useEffect(() => {
    setDares(null);
    if (daresOn) loadDares();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, daresOn]);

  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(() => setToast(""), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  function openDare() {
    setDareError("");
    setShowDare(true);
  }

  async function sendDare() {
    setDareSending(true);
    setDareError("");
    try {
      await api(`/groups/${id}/dares`, { method: "POST", body: { text: dareText.trim() } });
      setConfirmDare(false);
      setDareText("");
      setToast("Dare sent to your Chris-Child!");
      loadDares();
    } catch (err) {
      setDareError(err.message);
    } finally {
      setDareSending(false);
    }
  }

  async function markDone(dareId) {
    try {
      await api(`/dares/${dareId}/done`, { method: "POST" });
      await loadDares();
    } catch (err) {
      setDaresError(err.message);
    }
  }

  async function handleDraw() {
    setConfirmDraw(false);
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

  useEffect(() => {
    if (!showMembers) return undefined;
    const onDown = (e) => { if (anchorRef.current && !anchorRef.current.contains(e.target)) setShowMembers(false); };
    const onKey = (e) => { if (e.key === "Escape") setShowMembers(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("touchstart", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("touchstart", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [showMembers]);

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

  function openSettings() {
    setForm({ name: group.name, description: group.description || "", daresEnabled: !!group.daresEnabled });
    setSaveError("");
    setShowSettings(true);
  }

  async function saveSettings(e) {
    e.preventDefault();
    setSaving(true);
    setSaveError("");
    try {
      await api(`/groups/${id}`, { method: "PATCH", body: { name: form.name, description: form.description, daresEnabled: form.daresEnabled } });
      await load();
      setShowSettings(false);
    } catch (err) {
      setSaveError(err.message);
    } finally {
      setSaving(false);
    }
  }

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
    <Page
      title={group.name}
      back="/dashboard"
      action={
        <div className="head-actions">
          <div className="members-anchor" ref={anchorRef}>
            <button
              type="button"
              className="icon-btn"
              aria-label="Members"
              title="Members"
              aria-haspopup="dialog"
              aria-expanded={showMembers}
              onClick={() => setShowMembers((s) => !s)}
            >
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="9" cy="8" r="3.5" />
                <path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6" />
                <circle cx="17.5" cy="9" r="2.5" />
                <path d="M17 14.2c2.7.2 4.5 2 4.5 4.8" />
              </svg>
            </button>
            {showMembers && (
              <>
                <div className="sheet-backdrop" aria-hidden="true" />
                <div className="members-pop" role="dialog" aria-label="Members">
                  <div className="pop-head">
                    <h2>Members ({members.length})</h2>
                    <button type="button" className="x-btn" aria-label="Close members" onClick={() => setShowMembers(false)}>&times;</button>
                  </div>
                  <ul className="member-pills">
                    {members.map((m) => (
                      <li key={m.id} className={m.joined ? "mpill joined" : "mpill"}>
                        <span className="bow-icon" aria-hidden="true">&#10086;</span>
                        <span className="mname">{m.displayName}{m.isMe ? " (you)" : ""}</span>
                        <span className="mstatus">{m.joined ? "joined" : "not joined"}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            )}
          </div>
          {group.isAdmin && (
            <button type="button" className="icon-btn" aria-label="Group settings" title="Group settings" onClick={openSettings}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="3" />
                <path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M18.7 5.3l-2.1 2.1M7.4 16.6l-2.1 2.1" />
              </svg>
            </button>
          )}
        </div>
      }
    >
      <div className="group-layout">
        <div className="group-main">
          {(group.description || (group.daresEnabled && !group.isAdmin)) && (
            <div className="note-row">
              {group.description && (
                <div className="envelope">
                  <div className="note">
                    <svg className="clip" width="22" height="46" viewBox="0 0 22 46" aria-hidden="true">
                      <path d="M7 40V10a4 4 0 0 1 8 0v26a7 7 0 0 1-14 0V12" fill="none" stroke="#C9A35B" strokeWidth="2.5" strokeLinecap="round" transform="translate(3 0)" />
                    </svg>
                    <p>{group.description}</p>
                  </div>
                </div>
              )}
              {group.daresEnabled && !group.isAdmin && (
                <div className="dare-pill-wrap">
                  <button type="button" className="secondary" onClick={openDare} disabled={!group.drawn}>Send dare</button>
                  {!group.drawn && <span className="muted">After the draw</span>}
                </div>
              )}
            </div>
          )}

          <section className="panel">
            <h2>Chits</h2>
            {!group.drawn && <p className="muted">Chits appear once the admin draws names.</p>}
            {group.drawn && (data.revealed || openedName) && (
              <motion.div
                className="chit opened"
                initial={{ rotateY: 90, opacity: 0 }}
                animate={{ rotateY: 0, opacity: 1 }}
                transition={{ duration: 0.4 }}
              >
                <span className="hole" aria-hidden="true" />
                <p className="muted">Your Chris-Child is</p>
                <p className="chit-name">{openedName ?? data.childName}</p>
                <p className="muted">Keep it secret!</p>
              </motion.div>
            )}
            {group.drawn && !data.revealed && !openedName && (
              <ShuffleChits members={members} onPick={openChit} disabled={opening} />
            )}
            {chitError && <p className="error" role="alert">{chitError}</p>}
          </section>

          {daresOn && (
            <>
              <section className="panel">
                <h2>Dares for you</h2>
                {daresError && <p className="error" role="alert">{daresError}</p>}
                {dares && dares.received.length === 0 && <p className="muted">No dares yet. Your Chris-Mom may be plotting...</p>}
                <ul className="dare-list">
                  {dares?.received.map((d) => (
                    <li key={d.id} className={d.done ? "dare done" : "dare"}>
                      <span className="dare-from">From your Chris-Mom</span>
                      <p>{d.text}</p>
                      {d.done ? (
                        <span className="dare-status">Done &#10003;</span>
                      ) : (
                        <button type="button" onClick={() => markDone(d.id)}>Done</button>
                      )}
                    </li>
                  ))}
                </ul>
              </section>
              <section className="panel">
                <h2>Dares you sent</h2>
                {dares && dares.sent.length === 0 && <p className="muted">You haven&apos;t sent any dares yet.</p>}
                <ul className="dare-list">
                  {dares?.sent.map((d) => (
                    <li key={d.id} className={d.done ? "dare done" : "dare"}>
                      <p>{d.text}</p>
                      <span className="dare-status">{d.done ? "Done \u2713" : "Not done yet"}</span>
                    </li>
                  ))}
                </ul>
              </section>
            </>
          )}
        </div>

        <aside className="group-side">
          {group.isAdmin && (
            <section className="panel">
              <h2>Invite</h2>
              <input readOnly value={inviteLink} onFocus={(e) => e.target.select()} aria-label="Invite link" />
              <div className="row left">
                <button type="button" className="outline" onClick={copyLink}>{copied ? "Copied!" : "Copy link"}</button>
                <a className="btn red" href={waHref} target="_blank" rel="noreferrer">Share on WhatsApp</a>
              </div>
            </section>
          )}

          {group.isAdmin && group.daresEnabled && (
            <section className="panel">
              <h2>Send a dare</h2>
              <p className="muted">Challenge your Chris-Child. They won&apos;t know it&apos;s you.</p>
              <button type="button" onClick={openDare} disabled={!group.drawn}>Send a dare</button>
              {!group.drawn && <p className="muted">Available after the draw.</p>}
            </section>
          )}

          {group.isAdmin && (
            <section className="panel">
              <h2>Send Chris-Child</h2>
              {group.drawn ? (
                <p>Already drawn. Members are locked.</p>
              ) : (
                <>
                  <button type="button" onClick={() => setConfirmDraw(true)} disabled={drawing || members.length < 3}>
                    {drawing ? "Sending..." : "Send Chris-Child"}
                  </button>
                  {members.length < 3 && <p className="muted">You need at least 3 members.</p>}
                </>
              )}
              {actionError && <p className="error" role="alert">{actionError}</p>}
            </section>
          )}
        </aside>
      </div>

      <Modal
        open={showDare}
        title="Send a dare"
        confirmLabel="Send"
        onConfirm={() => {
          if (!dareText.trim()) return setDareError("Write your dare first.");
          setDareError("");
          setShowDare(false);
          setConfirmDare(true);
        }}
        onClose={() => setShowDare(false)}
      >
        <div className="form">
          <label>
            Your dare for your Chris-Child
            <textarea rows={4} maxLength={280} value={dareText} onChange={(e) => setDareText(e.target.value)} />
          </label>
          <span className="muted char-count">{dareText.length}/280</span>
          {dareError && <p className="error" role="alert">{dareError}</p>}
        </div>
      </Modal>

      <Modal
        open={confirmDare}
        title="Are you sure?"
        confirmLabel={dareSending ? "Sending..." : "Send"}
        cancelLabel="Edit"
        busy={dareSending}
        onConfirm={sendDare}
        onClose={() => { setConfirmDare(false); setShowDare(true); }}
      >
        <p>Send this dare to your Chris-Child?</p>
        <blockquote className="dare-preview">{dareText.trim()}</blockquote>
        {dareError && <p className="error" role="alert">{dareError}</p>}
      </Modal>

      {toast && <div className="toast" role="status">{toast}</div>}

      <Modal
        open={confirmDraw}
        title="Send Chris-Child?"
        confirmLabel="Send"
        onConfirm={handleDraw}
        onClose={() => setConfirmDraw(false)}
      >
        <p>This sends Chris-Child to everyone. It can&apos;t be undone, and members will be locked.</p>
      </Modal>

      <Modal
        open={showSettings}
        title="Group settings"
        confirmLabel={saving ? "Saving..." : "Save"}
        busy={saving}
        onConfirm={saveSettings}
        onClose={() => setShowSettings(false)}
      >
        <div className="form">
          <label>
            Group name
            <input value={form.name} maxLength={100} required onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </label>
          <label>
            Description
            <textarea rows={3} maxLength={500} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </label>
          <label className="toggle">
            <input type="checkbox" role="switch" checked={form.daresEnabled} onChange={(e) => setForm({ ...form, daresEnabled: e.target.checked })} />
            <span>Enable dares<small>Members can send secret dares to their Chris-Child.</small></span>
          </label>
          {saveError && <p className="error" role="alert">{saveError}</p>}
        </div>
      </Modal>
    </Page>
  );
}
