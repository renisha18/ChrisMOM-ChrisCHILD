import { Router } from "express";
import crypto from "crypto";
import db from "../db.js";
import { encrypt, decrypt } from "../lib/crypto.js";

const router = Router();

// Positive int4 or null, so junk/huge ids give a 404/400 instead of a DB error.
const toId = (v) => {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n < 2147483647 ? n : null;
};

function requireAuth(req, res, next) {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "Please log in." });
  next();
}
router.use("/groups", requireAuth);

const CODE_CHARS = "abcdefghijkmnpqrstuvwxyz23456789"; // no look-alikes
function makeCode() {
  let code = "";
  for (let i = 0; i < 8; i++) code += CODE_CHARS[crypto.randomInt(CODE_CHARS.length)];
  return code;
}

// My groups (created or joined)
router.get("/groups", async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT g.id, g.name, g.description, g.drawn_at, (g.admin_id = $1) AS is_admin,
              (SELECT COUNT(*)::int FROM group_members m WHERE m.group_id = g.id) AS member_count
       FROM groups g
       JOIN group_members me ON me.group_id = g.id AND me.user_id = $1
       ORDER BY g.created_at DESC`,
      [req.user.id]
    );
    res.json({ groups: rows });
  } catch (err) {
    console.error("List groups error:", err);
    res.status(500).json({ error: "Could not load your groups." });
  }
});

// Create group; creator's own name is auto-claimed by the creator.
router.post("/groups", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const description = String(req.body.description || "").trim();
  const myName = String(req.body.myName || "").trim();
  const others = Array.isArray(req.body.members)
    ? req.body.members.map((m) => String(m || "").trim()).filter(Boolean)
    : [];

  if (!name || name.length > 100) return res.status(400).json({ error: "Group name is required (max 100 characters)." });
  if (description.length > 500) return res.status(400).json({ error: "Description is too long (max 500 characters)." });
  if (!myName) return res.status(400).json({ error: "Enter your name in this group." });
  const all = [myName, ...others];
  if (all.some((n) => n.length > 50)) return res.status(400).json({ error: "Names must be 50 characters or fewer." });
  if (new Set(all.map((n) => n.toLowerCase())).size !== all.length) {
    return res.status(400).json({ error: "Each name must be unique." });
  }
  if (all.length > 100) return res.status(400).json({ error: "Too many members (max 100)." });

  let client;
  try {
    client = await db.connect();
    await client.query("BEGIN");
    let group;
    for (let attempt = 0; attempt < 5 && !group; attempt++) {
      await client.query("SAVEPOINT code_try");
      try {
        const r = await client.query(
          `INSERT INTO groups (name, description, invite_code, admin_id)
           VALUES ($1, $2, $3, $4) RETURNING id`,
          [name, description || null, makeCode(), req.user.id]
        );
        group = r.rows[0];
      } catch (e) {
        if (e.code !== "23505") throw e;
        await client.query("ROLLBACK TO SAVEPOINT code_try");
      }
    }
    if (!group) throw new Error("Could not generate invite code");
    await client.query(
      "INSERT INTO group_members (group_id, display_name, user_id) VALUES ($1, $2, $3)",
      [group.id, myName, req.user.id]
    );
    for (const n of others) {
      await client.query("INSERT INTO group_members (group_id, display_name) VALUES ($1, $2)", [group.id, n]);
    }
    await client.query("COMMIT");
    res.status(201).json({ id: group.id });
  } catch (err) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error("Create group error:", err);
    res.status(500).json({ error: "Could not create the group. Please try again." });
  } finally {
    if (client) client.release();
  }
});

// Group detail: members only
router.get("/groups/:id", async (req, res) => {
  try {
    const id = toId(req.params.id);
    if (!id) return res.status(404).json({ error: "Group not found." });
    const { rows } = await db.query("SELECT * FROM groups WHERE id = $1", [id]);
    const group = rows[0];
    const members = group
      ? (
          await db.query(
            `SELECT id, display_name, (user_id IS NOT NULL) AS joined, (user_id = $2) AS is_me,
                    revealed_at, assigned_child
             FROM group_members WHERE group_id = $1 ORDER BY id`,
            [id, req.user.id]
          )
        ).rows
      : [];
    // Same response for missing group and non-member, so ids can't be probed.
    if (!group || !members.some((m) => m.is_me)) {
      return res.status(404).json({ error: "Group not found." });
    }
    const isAdmin = group.admin_id === req.user.id;
    // Only my own revealed chit is ever disclosed.
    const me = members.find((m) => m.is_me);
    let childName = null;
    if (group.drawn_at && me.revealed_at && me.assigned_child) {
      const child = members.find((m) => m.id === Number(decrypt(me.assigned_child)));
      childName = child ? child.display_name : null;
    }
    res.json({
      childName,
      revealed: !!me.revealed_at,
      group: {
        id: group.id,
        name: group.name,
        description: group.description,
        drawn: !!group.drawn_at,
        isAdmin,
        inviteCode: isAdmin ? group.invite_code : undefined,
      },
      members: members.map((m) => ({
        id: m.id,
        displayName: m.display_name,
        joined: m.joined,
        isMe: m.is_me,
      })),
    });
  } catch (err) {
    console.error("Get group error:", err);
    res.status(500).json({ error: "Could not load the group." });
  }
});

// Reveal my Chris-Child (any member, after the draw). Any chit opens to my own assignment.
router.post("/groups/:id/reveal", async (req, res) => {
  try {
    const id = toId(req.params.id);
    if (!id) return res.status(404).json({ error: "Group not found." });
    const { rows } = await db.query(
      `UPDATE group_members m SET revealed_at = COALESCE(m.revealed_at, now())
       FROM groups g
       WHERE g.id = m.group_id AND g.id = $1 AND m.user_id = $2
         AND g.drawn_at IS NOT NULL AND m.assigned_child IS NOT NULL
       RETURNING m.assigned_child`,
      [id, req.user.id]
    );
    if (!rows.length) {
      // Distinguish "not a member" (404) from "not drawn yet" (409) without leaking.
      const { rows: mem } = await db.query(
        "SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2",
        [id, req.user.id]
      );
      if (!mem.length) return res.status(404).json({ error: "Group not found." });
      return res.status(409).json({ error: "Names haven't been drawn yet." });
    }
    const childId = Number(decrypt(rows[0].assigned_child));
    const child = await db.query(
      "SELECT display_name FROM group_members WHERE id = $1 AND group_id = $2",
      [childId, id]
    );
    if (!child.rows.length) throw new Error("Assigned child not found");
    res.json({ childName: child.rows[0].display_name });
  } catch (err) {
    console.error("Reveal error:", err);
    res.status(500).json({ error: "Could not open your chit. Please try again." });
  }
});

// Draw (admin only): one cycle over shuffled members, so nobody gets themselves
// and everyone has exactly one Chris-Mom. Members are locked after this.
router.post("/groups/:id/draw", async (req, res) => {
  const id = toId(req.params.id);
  if (!id) return res.status(404).json({ error: "Group not found." });
  let client;
  try {
    client = await db.connect();
    await client.query("BEGIN");
    // Row lock so two simultaneous draws can't both pass the drawn_at check.
    const { rows } = await client.query("SELECT admin_id, drawn_at FROM groups WHERE id = $1 FOR UPDATE", [id]);
    const group = rows[0];
    if (!group || group.admin_id !== req.user.id) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Group not found." });
    }
    if (group.drawn_at) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Names have already been drawn." });
    }
    const { rows: members } = await client.query("SELECT id FROM group_members WHERE group_id = $1", [id]);
    if (members.length < 3) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "You need at least 3 members to draw." });
    }
    for (let i = members.length - 1; i > 0; i--) {
      const j = crypto.randomInt(i + 1);
      [members[i], members[j]] = [members[j], members[i]];
    }
    for (let i = 0; i < members.length; i++) {
      const child = members[(i + 1) % members.length];
      await client.query("UPDATE group_members SET assigned_child = $1 WHERE id = $2", [
        encrypt(child.id),
        members[i].id,
      ]);
    }
    await client.query("UPDATE groups SET drawn_at = now() WHERE id = $1", [id]);
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (err) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error("Draw error:", err);
    res.status(500).json({ error: "Could not draw names. Please try again." });
  } finally {
    if (client) client.release();
  }
});

export default router;
