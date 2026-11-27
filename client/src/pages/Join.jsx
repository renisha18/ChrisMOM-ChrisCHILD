import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";
import Page from "../components/Page.jsx";

export default function Join() {
  const { code } = useParams();
  const { user, loading: authLoading } = useAuth();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [memberId, setMemberId] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState("");
  const autoClaimed = useRef(false);

  function load() {
    return api(`/join/${code}`)
      .then((d) => {
        setData(d);
        return d;
      })
      .catch((err) => {
        setError(err.message);
        return null;
      });
  }

  async function claim(id) {
    setBusy(true);
    setError("");
    try {
      const d = await api(`/join/${code}/claim`, { method: "POST", body: { memberId: Number(id) } });
      navigate(`/groups/${d.groupId}`, { replace: true });
    } catch (err) {
      setError(err.message);
      setBusy(false);
      setMemberId("");
      await load(); // refresh the list of unclaimed names
    }
  }

  // Load preview once auth state is known (so alreadyMember/pending are accurate).
  useEffect(() => {
    if (authLoading) return;
    load().then((d) => {
      // Returned from login/register with a name chosen earlier: claim it now.
      if (d && user && d.pendingMemberId && !d.alreadyMember && !autoClaimed.current) {
        autoClaimed.current = true;
        claim(d.pendingMemberId);
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [code, authLoading, user?.id]);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!memberId) return setError("Choose your name.");
    if (user) return claim(memberId);
    setBusy(true);
    setError("");
    try {
      await api(`/join/${code}/pending`, { method: "POST", body: { memberId: Number(memberId) } });
      navigate("/login", { state: { from: `/join/${code}` } });
    } catch (err) {
      setError(err.message);
      setBusy(false);
      await load();
    }
  }

  const visible = (data?.names || []).filter((n) => n.displayName.toLowerCase().includes(query.trim().toLowerCase()));

  // Radio-style arrow key navigation; moving focus also selects.
  function onChipKey(e, i) {
    const move = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (move) {
      e.preventDefault();
      const next = visible[(i + move + visible.length) % visible.length];
      setMemberId(String(next.id));
      e.currentTarget.parentElement.querySelectorAll('[role="radio"]')[(i + move + visible.length) % visible.length]?.focus();
    } else if (e.key === "Enter") {
      e.preventDefault();
      e.currentTarget.click();
    }
  }

  const back = user ? "/dashboard" : "/";

  if (!data) {
    return (
      <Page narrow title="Join group" back={back}>
        {error ? <p className="error" role="alert">{error}</p> : <p>Loading...</p>}
      </Page>
    );
  }

  const { group, names, alreadyMember } = data;

  return (
    <Page narrow title={`Join ${group.name}`} back={back}>
      {group.description && <p>{group.description}</p>}

      {alreadyMember ? (
        <p>
          You're already in this group. <Link to={`/groups/${group.id}`}>Open it</Link>
        </p>
      ) : names.length === 0 ? (
        <p>All names in this group have been claimed. Ask the admin if you think this is a mistake.</p>
      ) : (
        <form onSubmit={handleSubmit} className="form card">
          <div className="name-picker">
            <span id="who-label" className="name-picker-label">Who are you?</span>
            {names.length > 12 && (
              <input
                type="search"
                className="name-search"
                placeholder="Search names..."
                aria-label="Search names"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            )}
            <div className="name-chips" role="radiogroup" aria-labelledby="who-label">
              {visible.map((n, i) => {
                const selected = String(memberId) === String(n.id);
                const tabbable = selected || (!visible.some((v) => String(v.id) === String(memberId)) && i === 0);
                return (
                  <button
                    key={n.id}
                    type="button"
                    role="radio"
                    aria-checked={selected}
                    tabIndex={tabbable ? 0 : -1}
                    className={`name-chip${selected ? " selected" : ""}${memberId && !selected ? " dim" : ""}`}
                    onClick={() => setMemberId(selected ? "" : String(n.id))}
                    onKeyDown={(e) => onChipKey(e, i)}
                  >
                    <span className="name-chip-text">{n.displayName}</span>
                    {selected && <span className="name-chip-check" aria-hidden="true">&#10003;</span>}
                  </button>
                );
              })}
              {visible.length === 0 && <p className="muted">No names match.</p>}
            </div>
          </div>
          {!user && <p className="muted">You'll be asked to log in or register first.</p>}
          {error && <p className="error" role="alert">{error}</p>}
          <button type="submit" disabled={busy}>{busy ? "Please wait..." : "Join group"}</button>
        </form>
      )}
      {(alreadyMember || names.length === 0) && error && <p className="error" role="alert">{error}</p>}
    </Page>
  );
}
