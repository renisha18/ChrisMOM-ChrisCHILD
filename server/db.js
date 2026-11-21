import pg from "pg";
import env from "dotenv";

env.config();

const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
});

db.on("error", (err) => {
  console.error("Unexpected DB pool error:", err);
});

export default db;
