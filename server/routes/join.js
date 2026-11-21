import { Router } from "express";
import db from "../db.js";

const router = Router();

async function findGroup(code) {
  if (!/^[a-z0-9]{8}$/i.test(code)) return null;
  const { rows } = await db.query(
    "SELECT id, name, description, drawn_at FROM groups WHERE invite_code = $1",
    [code]
  );
  return rows[0] || null;
}

// Public preview: group + unclaimed names. If logged in, whether already a member.
router.get("/join/:code", async (req, res) => {
  try {
    const group = await findGroup(req.params.code);
    if (!group) return res.status(404).json({ error: "This invite link is not valid." });

    const { rows: free } = await db.query(
      "SELECT id, display_name FROM group_members WHERE group_id = $1 AND user_id IS NULL ORDER BY display_name",
      [group.id]
    );
    let alreadyMember = false;
    if (req.isAuthenticated()) {
      const { rows } = await db.query(
        "SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2",
        [group.id, req.user.id]
      );
      alreadyMember = rows.length > 0;
    }
    const pending = req.session.pendingJoin;
    res.json({
      group: { id: group.id, name: group.name, description: group.description, drawn: !!group.drawn_at },
      names: free.map((m) => ({ id: m.id, displayName: m.display_name })),
      alreadyMember,
      pendingMemberId: pending && pending.code === req.params.code ? pending.memberId : null,
    });
  } catch (err) {
    console.error("Join preview error:", err);
    res.status(500).json({ error: "Could not load this invite." });
  }
});

// Not logged in: remember the chosen name in the session until after login/register.
router.post("/join/:code/pending", async (req, res) => {
  try {
    const group = await findGroup(req.params.code);
    if (!group) return res.status(404).json({ error: "This invite link is not valid." });
    const memberId = Number(req.body.memberId);
    const { rows } = await db.query(
      "SELECT 1 FROM group_members WHERE id = $1 AND group_id = $2 AND user_id IS NULL",
      [memberId, group.id]
    );
    if (!rows.length) return res.status(409).json({ error: "That name is no longer available." });
    req.session.pendingJoin = { code: req.params.code, memberId };
    res.json({ ok: true });
  } catch (err) {
    console.error("Pending join error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// Claim a name (logged in).
router.post("/join/:code/claim", async (req, res) => {
  try {
    if (!req.isAuthenticated()) return res.status(401).json({ error: "Please log in." });
    delete req.session.pendingJoin; // consumed whether or not the claim succeeds

    const group = await findGroup(req.params.code);
    if (!group) return res.status(404).json({ error: "This invite link is not valid." });
    const memberId = Number(req.body.memberId);
    if (!Number.isInteger(memberId)) return res.status(400).json({ error: "Choose a name." });

    const mine = await db.query(
      "SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2",
      [group.id, req.user.id]
    );
    if (mine.rows.length) {
      return res.status(409).json({ error: "You are already in this group.", groupId: group.id });
    }

    // Atomic: only succeeds if the name is still unclaimed.
    let result;
    try {
      result = await db.query(
        `UPDATE group_members SET user_id = $1
         WHERE id = $2 AND group_id = $3 AND user_id IS NULL RETURNING id`,
        [req.user.id, memberId, group.id]
      );
    } catch (e) {
      if (e.code === "23505") {
        return res.status(409).json({ error: "You are already in this group.", groupId: group.id });
      }
      throw e;
    }
    if (!result.rows.length) {
      return res.status(409).json({ error: "That name was just taken. Please choose another." });
    }
    res.json({ groupId: group.id });
  } catch (err) {
    console.error("Claim error:", err);
    res.status(500).json({ error: "Could not join the group. Please try again." });
  }
});

export default router;
