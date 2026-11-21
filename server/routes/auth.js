import { Router } from "express";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import db from "../db.js";

const router = Router();
const saltRounds = 10;

passport.use(
  new Strategy(async (username, password, cb) => {
    try {
      const { rows } = await db.query("SELECT * FROM users WHERE username = $1", [username]);
      if (!rows.length) return cb(null, false);
      const valid = await bcrypt.compare(password, rows[0].password_hash);
      return cb(null, valid ? rows[0] : false);
    } catch (err) {
      return cb(err);
    }
  })
);

passport.serializeUser((user, cb) => cb(null, user.id));
passport.deserializeUser(async (id, cb) => {
  try {
    const { rows } = await db.query("SELECT id, username FROM users WHERE id = $1", [id]);
    cb(null, rows[0] || false);
  } catch (err) {
    cb(err);
  }
});

const publicUser = (u) => ({ id: u.id, username: u.username });

router.get("/me", (req, res) => {
  res.json({ user: req.isAuthenticated() ? publicUser(req.user) : null });
});

router.post("/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({ error: "Username must be 3-50 characters." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }
    const hash = await bcrypt.hash(password, saltRounds);
    let rows;
    try {
      ({ rows } = await db.query(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username",
        [username, hash]
      ));
    } catch (err) {
      if (err.code === "23505") {
        return res.status(409).json({ error: "That username is taken." });
      }
      throw err;
    }
    req.login(rows[0], (err) => {
      if (err) {
        console.error("Login after register failed:", err);
        return res.status(500).json({ error: "Account created, but login failed. Please log in." });
      }
      res.status(201).json({ user: publicUser(rows[0]) });
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

router.post("/login", (req, res) => {
  passport.authenticate("local", (err, user) => {
    if (err) {
      console.error("Login error:", err);
      return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
    if (!user) return res.status(401).json({ error: "Wrong username or password." });
    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error("Login error:", loginErr);
        return res.status(500).json({ error: "Something went wrong. Please try again." });
      }
      res.json({ user: publicUser(user) });
    });
  })(req, res);
});

router.post("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ error: "Could not log out. Please try again." });
    }
    res.json({ ok: true });
  });
});

export default router;
