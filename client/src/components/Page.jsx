import { motion, useReducedMotion } from "framer-motion";
import { useNavigate } from "react-router-dom";

// Page wrapper: fade-in, optional Back pill to the logical parent route.
export default function Page({ title, back, narrow, hero, action, children }) {
  const navigate = useNavigate();
  const reduce = useReducedMotion();
  return (
    <motion.main
      className={["page", narrow && "narrow", hero && "hero"].filter(Boolean).join(" ")}
      initial={reduce ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      {back && (
        <button type="button" className="back" onClick={() => navigate(back)}>
          <span className="back-tag">Back</span>
          <svg className="back-eyelet" width="30" height="34" viewBox="0 0 30 34" aria-hidden="true">
            <path d="M17 17C9 9 -2 8 -3 15c-1 6 8 7 20 2" fill="none" stroke="#A3161E" strokeWidth="1.8" strokeLinecap="round" />
            <circle cx="17" cy="17" r="3.6" fill="#FBF4E6" stroke="#C9A35B" strokeWidth="1.6" />
          </svg>
        </button>
      )}
      {title && (action ? <div className="page-head"><h1>{title}</h1>{action}</div> : <h1>{title}</h1>)}
      {children}
    </motion.main>
  );
}
