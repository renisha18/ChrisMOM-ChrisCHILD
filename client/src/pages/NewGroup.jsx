import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";
import Page from "../components/Page.jsx";

export default function NewGroup() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [myName, setMyName] = useState("");
  const [members, setMembers] = useState(["", ""]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [daresEnabled, setDaresEnabled] = useState(false);

  const setMember = (i, v) => setMembers((m) => m.map((x, j) => (j === i ? v : x)));
  const addRow = () => setMembers((m) => [...m, ""]);
  const removeRow = (i) => setMembers((m) => m.filter((_, j) => j !== i));

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    const others = members.map((m) => m.trim()).filter(Boolean);
    const all = [myName.trim(), ...others].map((n) => n.toLowerCase());
    if (new Set(all).size !== all.length) {
      return setError("Each name must be unique.");
    }
    setBusy(true);
    try {
      const d = await api("/groups", {
        method: "POST",
        body: { name: name.trim(), description: description.trim(), myName: myName.trim(), members: others, daresEnabled },
      });
      navigate(`/groups/${d.id}`, { replace: true });
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <Page narrow title="Create group" back="/dashboard">
      <form onSubmit={handleSubmit} className="form">
        <label>
          Group name
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} required />
        </label>
        <label>
          Description
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} rows={3} />
        </label>
        <label>
          Your name in this group
          <input value={myName} onChange={(e) => setMyName(e.target.value)} maxLength={50} required />
        </label>

        <fieldset className="chips">
          <legend>Other members</legend>
          {members.map((m, i) => (
            <div className="member-row chip" key={i}>
              <input
                value={m}
                onChange={(e) => setMember(i, e.target.value)}
                placeholder={`Member ${i + 1}`}
                maxLength={50}
                aria-label={`Member ${i + 1} name`}
              />
              <button type="button" className="chip-x" onClick={() => removeRow(i)} aria-label={`Remove member ${i + 1}`}>
                &times;
              </button>
            </div>
          ))}
          <div className="add-row">
            <button type="button" className="outline" onClick={addRow}>+ Add member</button>
          </div>
        </fieldset>

        <label className="toggle">
          <input type="checkbox" role="switch" checked={daresEnabled} onChange={(e) => setDaresEnabled(e.target.checked)} />
          <span>Enable dares<small>Members can send secret dares to their Chris-Child.</small></span>
        </label>

        {error && <p className="error" role="alert">{error}</p>}
        <button type="submit" disabled={busy}>{busy ? "Creating..." : "Create group"}</button>
      </form>
    </Page>
  );
}
