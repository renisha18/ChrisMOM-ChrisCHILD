import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";
import { api } from "../api.js";
import Page from "../components/Page.jsx";
import Modal from "../components/Modal.jsx";

function Msg({ m }) {
  if (!m) return null;
  return <p className={m.ok ? "success" : "error"} role={m.ok ? "status" : "alert"}>{m.text}</p>;
}

export default function Account() {
  const { user, logout, clearUser, updateUser } = useAuth();
  const navigate = useNavigate();

  const [info, setInfo] = useState(null);
  const [infoError, setInfoError] = useState("");

  const [cur, setCur] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [pwMsg, setPwMsg] = useState(null);
  const [pwBusy, setPwBusy] = useState(false);

  const [name, setName] = useState(user.username);
  const [nameMsg, setNameMsg] = useState(null);
  const [nameBusy, setNameBusy] = useState(false);

  const [delOpen, setDelOpen] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [delBusy, setDelBusy] = useState(false);
  const [delError, setDelError] = useState("");
  const [outError, setOutError] = useState("");

  useEffect(() => {
    api("/account").then(setInfo).catch((e) => setInfoError(e.message));
  }, []);

  async function changePassword(e) {
    e.preventDefault();
    setPwMsg(null);
    if (pw.length < 6) return setPwMsg({ text: "New password must be at least 6 characters." });
    if (pw !== pw2) return setPwMsg({ text: "New passwords don't match." });
    setPwBusy(true);
    try {
      await api("/account/password", { method: "POST", body: { currentPassword: cur, newPassword: pw } });
      setCur(""); setPw(""); setPw2("");
      setPwMsg({ ok: true, text: "Password changed." });
    } catch (err) {
      setPwMsg({ text: err.message });
    } finally {
      setPwBusy(false);
    }
  }

  async function changeUsername(e) {
    e.preventDefault();
    setNameMsg(null);
    const next = name.trim();
    if (next === user.username) return setNameMsg({ text: "That's already your username." });
    setNameBusy(true);
    try {
      const d = await api("/account/username", { method: "POST", body: { username: next } });
      updateUser(d.user);
      setName(d.user.username);
      setNameMsg({ ok: true, text: "Username updated." });
    } catch (err) {
      setNameMsg({ text: err.message });
    } finally {
      setNameBusy(false);
    }
  }

  async function handleLogout() {
    try {
      await logout();
      navigate("/", { replace: true });
    } catch (err) {
      setOutError(err.message);
    }
  }

  async function deleteAccount() {
    setDelBusy(true);
    setDelError("");
    try {
      await api("/account", { method: "DELETE", body: { confirmUsername: confirm } });
      clearUser();
      navigate("/", { replace: true });
    } catch (err) {
      setDelError(err.message);
      setDelBusy(false);
    }
  }

  const blocked = info && (info.adminGroups.length > 0 || info.drawnGroups.length > 0);

  return (
    <Page narrow title="Account" back="/dashboard">
      <p>Signed in as <strong>{user.username}</strong>.</p>

      <form className="form card" onSubmit={changePassword}>
        <h2>Change password</h2>
        <label>Current password
          <input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" required />
        </label>
        <label>New password
          <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" minLength={6} required />
        </label>
        <label>Confirm new password
          <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" minLength={6} required />
        </label>
        <Msg m={pwMsg} />
        <button type="submit" disabled={pwBusy}>{pwBusy ? "Saving..." : "Change password"}</button>
      </form>

      <form className="form card" onSubmit={changeUsername}>
        <h2>Change username</h2>
        <label>Username
          <input value={name} onChange={(e) => setName(e.target.value)} autoComplete="username" minLength={3} maxLength={50} required />
        </label>
        <Msg m={nameMsg} />
        <button type="submit" disabled={nameBusy}>{nameBusy ? "Saving..." : "Change username"}</button>
      </form>

      <div className="form card danger-zone">
        <h2>Delete account</h2>
        {infoError && <p className="error" role="alert">{infoError}</p>}
        {!info && !infoError && <p>Checking your groups...</p>}
        {blocked && (
          <>
            {info.adminGroups.length > 0 && (
              <div>
                <p>You're the admin of these groups. Transfer admin to someone else or delete the group first:</p>
                <ul>{info.adminGroups.map((g) => <li key={g.id}><Link to={`/groups/${g.id}`}>{g.name}</Link></li>)}</ul>
              </div>
            )}
            {info.drawnGroups.length > 0 && (
              <div>
                <p>You're in these groups where names are already drawn. Ask the admin to reset the draw or remove you:</p>
                <ul>{info.drawnGroups.map((g) => <li key={g.id}><Link to={`/groups/${g.id}`}>{g.name}</Link></li>)}</ul>
              </div>
            )}
          </>
        )}
        {info && !blocked && (
          <>
            <p>This permanently deletes your account. Your names in groups become unclaimed.</p>
            <button type="button" className="secondary" onClick={() => { setConfirm(""); setDelError(""); setDelOpen(true); }}>Delete my account</button>
          </>
        )}
      </div>

      <div className="row left">
        <button type="button" className="secondary" onClick={handleLogout}>Log out</button>
      </div>
      {outError && <p className="error" role="alert">{outError}</p>}

      <Modal
        open={delOpen}
        title="Delete account?"
        onClose={() => setDelOpen(false)}
        onConfirm={deleteAccount}
        confirmLabel={delBusy ? "Deleting..." : "Delete account"}
        busy={delBusy}
        confirmDisabled={confirm !== user.username}
      >
        <p>This can't be undone. Type <strong>{user.username}</strong> to confirm.</p>
        <input value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" aria-label="Type your username" />
        {delError && <p className="error" role="alert">{delError}</p>}
      </Modal>
    </Page>
  );
}
