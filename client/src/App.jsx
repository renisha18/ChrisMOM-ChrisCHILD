import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./auth.jsx";
import Landing from "./pages/Landing.jsx";
import HowToPlay from "./pages/HowToPlay.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import NewGroup from "./pages/NewGroup.jsx";
import Group from "./pages/Group.jsx";
import Account from "./pages/Account.jsx";
import Join from "./pages/Join.jsx";
import Page from "./components/Page.jsx";

function Protected({ children }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Page back="/"><p>Loading...</p></Page>;
  if (!user) return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/how-to-play" element={<HowToPlay />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route
        path="/dashboard"
        element={
          <Protected>
            <Dashboard />
          </Protected>
        }
      />
      <Route
        path="/groups/new"
        element={
          <Protected>
            <NewGroup />
          </Protected>
        }
      />
      <Route
        path="/groups/:id"
        element={
          <Protected>
            <Group />
          </Protected>
        }
      />
      <Route
        path="/account"
        element={
          <Protected>
            <Account />
          </Protected>
        }
      />
      <Route path="/join/:code" element={<Join />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
