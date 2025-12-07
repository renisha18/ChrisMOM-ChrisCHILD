import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import crypto from "crypto";

const app = express();
const port = 5001;
const saltRounds = 10;
env.config();
const ENCRYPT_KEY = process.env.ENCRYPT_KEY; // must be 32 bytes hex string (64 hex chars)
const IV_LENGTH = 16;

if (!ENCRYPT_KEY || ENCRYPT_KEY.length !== 64) {
  console.error(
    "ENCRYPT_KEY missing or invalid. Generate a 32-byte hex key and set ENCRYPT_KEY in .env"
  );
  // Do not exit automatically; developer can still run but encryption will fail when used.
}

function encrypt(text) {
  if (!ENCRYPT_KEY) throw new Error("ENCRYPT_KEY not configured");
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPT_KEY, "hex"),
    iv
  );
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decrypt(enc) {
  if (!enc) return null;
  if (!ENCRYPT_KEY) throw new Error("ENCRYPT_KEY not configured");
  const parts = enc.split(":");
  const iv = Buffer.from(parts.shift(), "hex");
  const encryptedText = parts.join(":");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPT_KEY, "hex"),
    iv
  );
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect()
  .then(() => console.log("Connected to Postgres"))
  .catch(err => console.log("DB Error:", err));


function isAdmin(req, res, next) {
  // Change this to your actual admin email
  const adminEmail = "Renisha";

  if (req.isAuthenticated() && req.user.email === adminEmail) {
    return next();
  }

  // Option 1: Show error
  // return res.status(403).send("Access denied: Admin only.");

  // Option 2: Redirect to home (cleaner)
  return res.redirect("/");
}

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/admin", isAdmin, async (req, res) => {
  try {
    const users = await db.query("SELECT email FROM users");
    res.render("admin.ejs", { users: users.rows });
  } catch (err) {
    console.error("Admin page error:", err);
    res.status(500).send("Server error loading admin page");
  }
});

app.post("/generate", async (req, res) => {
  try {
    const usersRes = await db.query("SELECT email FROM users");
    let users = usersRes.rows.map((u) => u.email);

    if (users.length === 0) {
      return res.status(400).send("No users to assign.");
    }

    // Shuffle users
    let shuffled = [...users];
    shuffled.sort(() => Math.random() - 0.5);

    // Avoid self-assignment: reshuffle until no one has themselves (simple approach)
    let attempts = 0;
    while (users.some((u, i) => u === shuffled[i]) && attempts < 1000) {
      shuffled.sort(() => Math.random() - 0.5);
      attempts++;
    }
    if (users.some((u, i) => u === shuffled[i])) {
      return res
        .status(500)
        .send("Could not generate valid assignments without self-matching.");
    }

    // Save encrypted assignments in DB (assigned_child column expected)
    for (let i = 0; i < users.length; i++) {
      const plainAssigned = shuffled[i];
      const enc = encrypt(plainAssigned);
      await db.query(
        "UPDATE users SET assigned_child= $1 WHERE email = $2",
        [enc, users[i]]
      );
    }

    res.send("Generated successfully!");
  } catch (err) {
    console.error("Generate error:", err);
    res.status(500).send("Server error while generating");
  }
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const email = req.user.email;
      const result = await db.query(
        "SELECT assigned_child FROM users WHERE email = $1",
        [email]
      );

      const enc = result.rows[0]?.assigned_child;
      const childName = enc ? decrypt(enc) : null;

      res.render("secrets.ejs", { childName, user: req.user });
    } catch (err) {
      console.error("Error fetching assigned child:", err);
      res.status(500).send("Server error");
    }
  } else {
    res.redirect("/login");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
