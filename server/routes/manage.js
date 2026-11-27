import { Router } from "express";
import db from "../db.js";

// Admin group management + member leave. Every id is re-checked against the group on the server.
const router = Router();
const MAX_MEMBERS = 100;

const toId = (v) => {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n < 2147483647 ? n : null;
};

router.use("/groups", (req, res, next) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "Please log in." });
  next();
});

const fail = (status, error) => ({ fail: { status, error } });

function cleanName(v) {
  const name = String(v ?? "").trim();
  if (!name) return { error: "Enter a name." };
  if (name.length > 50) return { error: "Names must be 50 characters or fewer." };
  return { name };
}

// Runs fn(client, groupId) in a transaction. fn returns { json, status? } to commit or { fail } to roll back.
async function tx(req, res, label, fn) {
  const groupId = toId(req.params.id);
  if (!groupId) return res.status(404).json({ error: "Group not found." });
  let client;
  try {
    client = await db.connect();
    await client.query("BEGIN");
    const out = await fn(client, groupId);
    if (out.fail) {
      await client.query("ROLLBACK");
      return res.status(out.fail.status).json({ error: out.fail.error });
    }
    await client.query("COMMIT");
    res.status(out.status || 200).json(out.json || { ok: true });
  } catch (err) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    if (err.code === "23505") return res.status(409).json({ error: "That name is already used in this group." });
    console.error(`${label} error:`, err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  } finally {
    if (client) client.release();
  }
}

// Locks the group row; same 404 for missing group and non-member. admin=true also requires admin.
async function loadGroup(client, groupId, userId, admin) {
  const { rows } = await client.query(
    `SELECT g.id, g.name, g.admin_id, g.drawn_at, m.id AS my_member_id
     FROM groups g JOIN group_members m ON m.group_id = g.id AND m.user_id = $2
     WHERE g.id = $1 FOR UPDATE OF g`,
    [groupId, userId]
  );
  const g = rows[0];
  if (!g) return fail(404, "Group not found.");
  if (admin && g.admin_id !== userId) return fail(403, "Only the admin can do that.");
  return { g };
}

async function loadMember(client, groupId, memberId) {
  const mid = toId(memberId);
  if (!mid) return null;
  const { rows } = await client.query("SELECT id, user_id FROM group_members WHERE id = $1 AND group_id = $2", [mid, groupId]);
  return rows[0] || null;
}

const nameTaken = async (client, groupId, name, exceptId = 0) =>
  (await client.query(
    "SELECT 1 FROM group_members WHERE group_id = $1 AND lower(display_name) = lower($2) AND id <> $3",
    [groupId, name, exceptId]
  )).rows.length > 0;

// Add a member name (before draw only).
router.post("/groups/:id/members", (req, res) =>
  tx(req, res, "Add member", async (c, groupId) => {
    const ctx = await loadGroup(c, groupId, req.user.id, true);
    if (ctx.fail) return ctx;
    if (ctx.g.drawn_at) return fail(409, "Names are drawn, so members are locked. Reset the draw first.");
    const n = cleanName(req.body?.name);
    if (n.error) return fail(400, n.error);
    const { rows } = await c.query("SELECT COUNT(*)::int AS n FROM group_members WHERE group_id = $1", [groupId]);
    if (rows[0].n >= MAX_MEMBERS) return fail(400, `Too many members (max ${MAX_MEMBERS}).`);
    if (await nameTaken(c, groupId, n.name)) return fail(409, "That name is already used in this group.");
    await c.query("INSERT INTO group_members (group_id, display_name) VALUES ($1, $2)", [groupId, n.name]);
    return { status: 201, json: { ok: true } };
  })
);

// Rename a member (any time).
router.patch("/groups/:id/members/:mid", (req, res) =>
  tx(req, res, "Rename member", async (c, groupId) => {
    const ctx = await loadGroup(c, groupId, req.user.id, true);
    if (ctx.fail) return ctx;
    const m = await loadMember(c, groupId, req.params.mid);
    if (!m) return fail(404, "Member not found.");
    const n = cleanName(req.body?.displayName);
    if (n.error) return fail(400, n.error);
    if (await nameTaken(c, groupId, n.name, m.id)) return fail(409, "That name is already used in this group.");
    await c.query("UPDATE group_members SET display_name = $1 WHERE id = $2", [n.name, m.id]);
    return { json: { ok: true } };
  })
);

// Remove a member (before draw only).
router.delete("/groups/:id/members/:mid", (req, res) =>
  tx(req, res, "Remove member", async (c, groupId) => {
    const ctx = await loadGroup(c, groupId, req.user.id, true);
    if (ctx.fail) return ctx;
    const m = await loadMember(c, groupId, req.params.mid);
    if (!m) return fail(404, "Member not found.");
    if (m.id === ctx.g.my_member_id) return fail(400, "You can't remove yourself. Transfer admin first, then leave.");
    if (ctx.g.drawn_at) return fail(409, "Reset the draw first.");
    await c.query("DELETE FROM group_members WHERE id = $1", [m.id]);
    return { json: { ok: true } };
  })
);

// Unclaim: detach the account but keep the row and its assignment, so the name can be claimed again.
router.post("/groups/:id/members/:mid/unclaim", (req, res) =>
  tx(req, res, "Unclaim member", async (c, groupId) => {
    const ctx = await loadGroup(c, groupId, req.user.id, true);
    if (ctx.fail) return ctx;
    const m = await loadMember(c, groupId, req.params.mid);
    if (!m) return fail(404, "Member not found.");
    if (m.id === ctx.g.my_member_id) return fail(400, "You can't unclaim your own name.");
    if (!m.user_id) return fail(409, "That name isn't claimed.");
    await c.query("UPDATE group_members SET user_id = NULL WHERE id = $1", [m.id]);
    return { json: { ok: true } };
  })
);

// Reset the draw: clear assignments/reveals and delete this group's dares.
router.post("/groups/:id/reset", (req, res) =>
  tx(req, res, "Reset draw", async (c, groupId) => {
    const ctx = await loadGroup(c, groupId, req.user.id, true);
    if (ctx.fail) return ctx;
    if (!ctx.g.drawn_at) return fail(409, "Names haven't been drawn yet.");
    await c.query("DELETE FROM dares WHERE group_id = $1", [groupId]);
    await c.query("UPDATE group_members SET assigned_child = NULL, revealed_at = NULL WHERE group_id = $1", [groupId]);
    await c.query("UPDATE groups SET drawn_at = NULL WHERE id = $1", [groupId]);
    return { json: { ok: true } };
  })
);

// Transfer admin to another joined member.
router.post("/groups/:id/transfer", (req, res) =>
  tx(req, res, "Transfer admin", async (c, groupId) => {
    const ctx = await loadGroup(c, groupId, req.user.id, true);
    if (ctx.fail) return ctx;
    const m = await loadMember(c, groupId, req.body?.memberId);
    if (!m) return fail(404, "Member not found.");
    if (m.id === ctx.g.my_member_id) return fail(400, "You're already the admin.");
    if (!m.user_id) return fail(409, "That person hasn't joined yet. Choose a member who has joined.");
    await c.query("UPDATE groups SET admin_id = $1 WHERE id = $2", [m.user_id, groupId]);
    return { json: { ok: true } };
  })
);

// Leave (before draw only; admin must transfer first). Deletes the member's row.
router.post("/groups/:id/leave", (req, res) =>
  tx(req, res, "Leave group", async (c, groupId) => {
    const ctx = await loadGroup(c, groupId, req.user.id, false);
    if (ctx.fail) return ctx;
    if (ctx.g.admin_id === req.user.id) return fail(403, "Transfer admin to someone else before leaving.");
    if (ctx.g.drawn_at) return fail(409, "Names are drawn. Ask the admin.");
    await c.query("DELETE FROM group_members WHERE id = $1", [ctx.g.my_member_id]);
    return { json: { ok: true } };
  })
);

// Delete the whole group (admin; must repeat the group name). Cascades to members and dares.
router.delete("/groups/:id", (req, res) =>
  tx(req, res, "Delete group", async (c, groupId) => {
    const ctx = await loadGroup(c, groupId, req.user.id, true);
    if (ctx.fail) return ctx;
    if (String(req.body?.confirmName ?? "").trim() !== ctx.g.name) return fail(400, "Type the group name exactly to delete it.");
    await c.query("DELETE FROM groups WHERE id = $1", [groupId]);
    return { json: { ok: true } };
  })
);

export default router;
