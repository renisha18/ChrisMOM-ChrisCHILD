import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";

const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Themed dialog: backdrop, focus trap, Esc to close. Wrapping in a form lets Enter submit.
// Props: open, title, onClose, onConfirm (omit for an info/alert modal), confirmLabel, cancelLabel, busy, confirmDisabled.
export default function Modal({ open, title, onClose, onConfirm, confirmLabel = "Confirm", cancelLabel = "Cancel", busy = false, confirmDisabled = false, children }) {
  const card = useRef(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    if (!open) return undefined;
    const prev = document.activeElement;
    const first = card.current?.querySelector("input, textarea, select") || card.current?.querySelector(FOCUSABLE);
    first?.focus();
    const onKey = (e) => {
      if (e.key === "Escape") { e.stopPropagation(); closeRef.current?.(); return; }
      if (e.key !== "Tab" || !card.current) return;
      const els = [...card.current.querySelectorAll(FOCUSABLE)];
      if (!els.length) return;
      const a = els[0], z = els[els.length - 1];
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus(); }
      else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
      else if (!card.current.contains(document.activeElement)) { e.preventDefault(); a.focus(); }
    };
    document.addEventListener("keydown", onKey);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
      prev?.focus?.();
    };
  }, [open]);

  if (!open) return null;
  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onClose?.(); }}>
      <form
        className="modal-card"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={card}
        onSubmit={(e) => { e.preventDefault(); if (!busy) onConfirm?.(e); }}
      >
        <h2>{title}</h2>
        <div className="modal-body">{children}</div>
        <div className="modal-actions">
          {onConfirm && <button type="button" className="outline" onClick={onClose} disabled={busy}>{cancelLabel}</button>}
          {onConfirm
            ? <button type="submit" disabled={busy || confirmDisabled}>{confirmLabel}</button>
            : <button type="button" onClick={onClose}>{confirmLabel === "Confirm" ? "OK" : confirmLabel}</button>}
        </div>
      </form>
    </div>,
    document.body
  );
}
