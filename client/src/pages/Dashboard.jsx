import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";
import Page from "../components/Page.jsx";

export default function Dashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState("");

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
      <p>You haven't joined any groups yet.</p>
      {error && <p className="error" role="alert">{error}</p>}
      <button type="button" className="secondary" onClick={handleLogout}>Log out</button>
    </Page>
  );
}
