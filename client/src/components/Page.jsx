import { motion, useReducedMotion } from "framer-motion";
import { useNavigate } from "react-router-dom";

// Page wrapper: fade-in, optional Back pill to the logical parent route.
export default function Page({ title, back, wide, children }) {
  const navigate = useNavigate();
  const reduce = useReducedMotion();
  return (
    <motion.main
      className={wide ? "page wide" : "page"}
      initial={reduce ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      {back && (
        <button type="button" className="back" onClick={() => navigate(back)}>
          &larr; Back
        </button>
      )}
      {title && <h1>{title}</h1>}
      {children}
    </motion.main>
  );
}
