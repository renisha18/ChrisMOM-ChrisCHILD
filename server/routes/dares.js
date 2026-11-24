import { Router } from "express";
import db from "../db.js";
import { decrypt } from "../lib/crypto.js";

const router = Router();
const MAX_LEN = 280;
const MAX_PER_DAY = 10;

const toId = (v) => {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n < 2147483647 ? n : null;
};

function requireAuth(req, res, next) {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "Please log in." });
  next();
}
router.use("/groups/:id/dares", requireAuth);
router.use("/dares", requireAuth);

// Group + my member row, or null (same 404 for missing group and non-member).
// lock=true takes a row lock on my member row so the daily limit can't be raced.
async function loadContext(q, groupId, userId, lock = false) {
  const { rows } = await q.query(
    `SELECT g.drawn_at, g.dares_enabled, m.id AS member_id, m.assigned_child
     FROM groups g JOIN group_members m ON m.group_id = g.id AND m.user_id = $2
     WHERE g.id = $1 ${lock ? "FOR UPDATE OF m" : ""}`,
    [groupId, userId]
  );
  return rows[0] || null;
}

function readiness(ctx) {
  if (!ctx.dares_enabled) return { status: 409, error: "Dares aren't enabled for this group." };
  if (!ctx.drawn_at) return { status: 409, error: "Names haven't been drawn yet." };
  return null;
}

// Send a dare to my Chris-Child (recipient is derived server-side only).
router.post("/groups/:id/dares", async (req, res) => {
  const groupId = toId(req.params.id);
  if (!groupId) return res.status(404).json({ error: "Group not found." });
  const text = String(req.body?.text ?? "").trim();
  if (!text) return res.status(400).json({ error: "Write your dare first." });
  if (text.length > MAX_LEN) return res.status(400).json({ error: `Dares can be at most ${MAX_LEN} characters.` });

  let client;
  try {
    client = await db.connect();
    await client.query("BEGIN");
    const ctx = await loadContext(client, groupId, req.user.id, true);
    if (!ctx) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Group not found." });
    }
    const notReady = readiness(ctx);
    if (notReady || !ctx.assigned_child) {
      await client.query("ROLLBACK");
      const r = notReady || { status: 409, error: "Names haven't been drawn yet." };
      return res.status(r.status).json({ error: r.error });
    }
    const { rows: cnt } = await client.query(
      "SELECT COUNT(*)::int AS n FROM dares WHERE from_member_id = $1 AND created_at > now() - interval '24 hours'",
      [ctx.member_id]
    );
    if (cnt[0].n >= MAX_PER_DAY) {
      await client.query("ROLLBACK");
      return res.status(429).json({ error: `You can send up to ${MAX_PER_DAY} dares a day. Try again tomorrow.` });
    }
    const toId_ = Number(decrypt(ctx.assigned_child));
    await client.query(
      "INSERT INTO dares (group_id, from_member_id, to_member_id, text) VALUES ($1, $2, $3, $4)",
      [groupId, ctx.member_id, toId_, text]
    );
    await client.query("COMMIT");
    res.status(201).json({ ok: true });
  } catch (err) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error("Send dare error:", err);
    res.status(500).json({ error: "Could not send the dare. Please try again." });
  } finally {
    if (client) client.release();
  }
});

// My sent dares + dares I received (never any sender info). Marks received as seen.
router.get("/groups/:id/dares", async (req, res) => {
  try {
    const groupId = toId(req.params.id);
    if (!groupId) return res.status(404).json({ error: "Group not found." });
    const ctx = await loadContext(db, groupId, req.user.id);
    if (!ctx) return res.status(404).json({ error: "Group not found." });
    const notReady = readiness(ctx);
    if (notReady) return res.status(notReady.status).json({ error: notReady.error });

    const [sent, received] = await Promise.all([
      db.query(
        "SELECT id, text, created_at, done_at FROM dares WHERE from_member_id = $1 ORDER BY created_at DESC",
        [ctx.member_id]
      ),
      db.query(
        "SELECT id, text, created_at, done_at FROM dares WHERE to_member_id = $1 ORDER BY created_at DESC",
        [ctx.member_id]
      ),
    ]);
    await db.query("UPDATE dares SET seen_at = now() WHERE to_member_id = $1 AND seen_at IS NULL", [ctx.member_id]);
    const shape = (r) => ({ id: r.id, text: r.text, createdAt: r.created_at, done: !!r.done_at, doneAt: r.done_at });
    res.json({ sent: sent.rows.map(shape), received: received.rows.map(shape) });
  } catch (err) {
    console.error("List dares error:", err);
    res.status(500).json({ error: "Could not load dares." });
  }
});

// Recipient marks a dare done.
router.post("/dares/:id/done", async (req, res) => {
  try {
    const id = toId(req.params.id);
    if (!id) return res.status(404).json({ error: "Dare not found." });
    const { rows } = await db.query(
      `UPDATE dares d SET done_at = COALESCE(d.done_at, now()), seen_at = COALESCE(d.seen_at, now())
       FROM group_members m
       WHERE d.id = $1 AND m.id = d.to_member_id AND m.user_id = $2
       RETURNING d.id`,
      [id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: "Dare not found." });
    res.json({ ok: true });
  } catch (err) {
    console.error("Dare done error:", err);
    res.status(500).json({ error: "Could not update the dare." });
  }
});

export default router;
