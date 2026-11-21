import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import passport from "passport";
import path from "path";
import { fileURLToPath } from "url";
import db from "./db.js";
import authRoutes from "./routes/auth.js";
import groupRoutes from "./routes/groups.js";
import joinRoutes from "./routes/join.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.PORT || 5001;
const isProd = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET) {
  console.error("SESSION_SECRET is not set. Add it to .env");
  process.exit(1);
}

if (isProd) app.set("trust proxy", 1);

const PgStore = connectPgSimple(session);

app.use(express.json());
app.use(
  session({
    store: new PgStore({ pool: db, tableName: "session" }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProd,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use("/api", authRoutes);
app.use("/api", groupRoutes);
app.use("/api", joinRoutes);
app.use("/api", (req, res) => res.status(404).json({ error: "Not found." }));

if (isProd) {
  const dist = path.join(__dirname, "../client/dist");
  app.use(express.static(dist));
  app.get("*", (req, res) => res.sendFile(path.join(dist, "index.html")));
}

// Last-resort error handler: never crash, always return JSON.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid request." });
  }
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Something went wrong. Please try again." });
});

process.on("unhandledRejection", (err) => console.error("Unhandled rejection:", err));

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
