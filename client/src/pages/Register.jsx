import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";
import Page from "../components/Page.jsx";
import AuthForm from "../components/AuthForm.jsx";

export default function Register() {
  const { user, loading, register } = useAuth();
  const navigate = useNavigate();
  const from = useLocation().state?.from || "/dashboard";

  if (loading) return <Page narrow title="Create account" back="/"><p>Loading...</p></Page>;
  if (user) return <Navigate to={from} replace />;

  return (
    <Page narrow title="Create account" back="/">
      <AuthForm
        submitLabel="Register"
        onSubmit={async (u, p) => {
          await register(u, p);
          navigate(from, { replace: true });
        }}
      />
      <p>
        Already have an account? <Link to="/login" state={{ from }}>Log in</Link>
      </p>
    </Page>
  );
}
