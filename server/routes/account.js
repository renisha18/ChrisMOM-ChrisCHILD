import { Router } from "express";
import bcrypt from "bcryptjs";
import db from "../db.js";

const router = Router();
const saltRounds = 10;
const oops = { error: "Something went wrong. Please try again." };

router.use("/account", (req, res, next) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "Please log in." });
  next();
});

// Groups that stop the user deleting their account.
async function blockers(userId) {
  const admin = await db.query("SELECT id, name FROM groups WHERE admin_id = $1 ORDER BY name", [userId]);
  const drawn = await db.query(
    `SELECT g.id, g.name FROM groups g JOIN group_members m ON m.group_id = g.id
     WHERE m.user_id = $1 AND g.drawn_at IS NOT NULL AND g.admin_id <> $1 ORDER BY g.name`,
    [userId]
  );
  return { adminGroups: admin.rows, drawnGroups: drawn.rows };
}

router.get("/account", async (req, res) => {
  try {
    res.json(await blockers(req.user.id));
  } catch (err) {
    console.error("Account info error:", err);
    res.status(500).json(oops);
  }
});

router.post("/account/password", async (req, res) => {
  try {
    const current = String(req.body.currentPassword || "");
    const next = String(req.body.newPassword || "");
    if (next.length < 6) return res.status(400).json({ error: "New password must be at least 6 characters." });
    const { rows } = await db.query("SELECT password_hash FROM users WHERE id = $1", [req.user.id]);
    if (!rows.length || !(await bcrypt.compare(current, rows[0].password_hash))) {
      return res.status(400).json({ error: "Current password is wrong." });
    }
    await db.query("UPDATE users SET password_hash = $1 WHERE id = $2", [await bcrypt.hash(next, saltRounds), req.user.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json(oops);
  }
});

router.post("/account/username", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({ error: "Username must be 3-50 characters." });
    }
    try {
      await db.query("UPDATE users SET username = $1 WHERE id = $2", [username, req.user.id]);
    } catch (err) {
      if (err.code === "23505") return res.status(409).json({ error: "That username is taken." });
      throw err;
    }
    res.json({ user: { id: req.user.id, username } });
  } catch (err) {
    console.error("Change username error:", err);
    res.status(500).json(oops);
  }
});

router.delete("/account", async (req, res) => {
  try {
    const { adminGroups, drawnGroups } = await blockers(req.user.id);
    if (adminGroups.length || drawnGroups.length) {
      return res.status(409).json({ error: "Resolve your groups before deleting your account.", adminGroups, drawnGroups });
    }
    if (String(req.body.confirmUsername || "") !== req.user.username) {
      return res.status(400).json({ error: "Type your username exactly to confirm." });
    }
    const userId = req.user.id;
    // Member rows keep their names (user_id -> NULL via FK), so the names can be claimed again.
    await db.query("DELETE FROM users WHERE id = $1", [userId]);
    req.logout((err) => {
      if (err) console.error("Logout after delete failed:", err);
      res.json({ ok: true });
    });
  } catch (err) {
    console.error("Delete account error:", err);
    res.status(500).json(oops);
  }
});

export default router;
