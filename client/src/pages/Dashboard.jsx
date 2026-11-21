import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";
import { api } from "../api.js";
import Page from "../components/Page.jsx";

export default function Dashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [groups, setGroups] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api("/groups")
      .then((d) => setGroups(d.groups))
      .catch((err) => setError(err.message));
  }, []);

  async function handleLogout() {
    try {
      await logout();
      navigate("/", { replace: true });
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <Page title="Dashboard" back="/">
      <p>Hello, {user.username}!</p>
      <div className="row left">
        <Link className="btn" to="/groups/new">Create Group</Link>
        <button type="button" className="secondary" onClick={handleLogout}>Log out</button>
      </div>
      {error && <p className="error" role="alert">{error}</p>}
      <h2>My groups</h2>
      {groups === null && !error && <p>Loading...</p>}
      {groups?.length === 0 && <p>You haven't joined any groups yet.</p>}
      <ul className="list">
        {groups?.map((g) => (
          <li key={g.id}>
            <Link to={`/groups/${g.id}`}>
              <strong>{g.name}</strong>
            </Link>
            <span className="muted">
              {" "}· {g.member_count} members{g.is_admin ? " · admin" : ""}{g.drawn_at ? " · drawn" : ""}
            </span>
          </li>
        ))}
      </ul>
    </Page>
  );
}
