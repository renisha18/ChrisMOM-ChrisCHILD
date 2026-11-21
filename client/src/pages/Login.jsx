import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";
import Page from "../components/Page.jsx";
import AuthForm from "../components/AuthForm.jsx";

export default function Login() {
  const { user, loading, login } = useAuth();
  const navigate = useNavigate();
  const from = useLocation().state?.from || "/dashboard";

  if (loading) return <Page narrow title="Log in" back="/"><p>Loading...</p></Page>;
  if (user) return <Navigate to={from} replace />;

  return (
    <Page narrow title="Log in" back="/">
      <AuthForm
        submitLabel="Log in"
        onSubmit={async (u, p) => {
          await login(u, p);
          navigate(from, { replace: true });
        }}
      />
      <p>
        New here? <Link to="/register" state={{ from }}>Create an account</Link>
      </p>
    </Page>
  );
}
