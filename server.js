// server.js
// Kiwi Sales Counter: username+password auth, two per-user counters (green/yellow) + reset

const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const { v4: uuidv4 } = require("uuid");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === "production";

// ---------- DB (SQLite) ----------
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const dbFile = path.join(dataDir, "data.db");
const db = new sqlite3.Database(dbFile);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    green_count INTEGER NOT NULL DEFAULT 0,
    yellow_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  )`);
});

// ---------- App config ----------
app.set("trust proxy", 1); // for secure cookies behind proxies (Render)
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: PROD, // true on Render (https)
    },
  })
);

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}

function layout(title, body) {
  return `<!doctype html>
  <html>
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>${title}</title>
    <style>
      :root { --green:#22c55e; --yellow:#eab308; --bg:#0b1220; --card:#111827; --text:#e5e7eb; }
      body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background:#0b1220; color:#e5e7eb; }
      .wrap { max-width:820px; margin:40px auto; padding:0 16px; }
      .card { background:#111827; border:1px solid #1f2937; border-radius:16px; padding:24px; box-shadow:0 10px 30px rgba(0,0,0,.25); }
      h1 { margin:0 0 8px 0; font-size:28px; }
      h2 { margin:8px 0 16px; }
      a { color:#60a5fa; text-decoration:none; }
      input, button { font-size:16px; padding:10px 12px; border-radius:10px; border:1px solid #374151; background:#0b1220; color:#e5e7eb; }
      input { width:100%; }
      .row { display:flex; gap:10px; align-items:center; }
      .space { height:12px; }
      .actions { display:flex; gap:16px; align-items:center; justify-content:space-between; }
      .btns { display:flex; gap:24px; align-items:center; justify-content:flex-start; margin-top:14px; flex-wrap:wrap; }
      .circle { width:120px; height:120px; border-radius:9999px; display:flex; align-items:center; justify-content:center; font-size:28px; font-weight:700; }
      .green { background:var(--green); color:#07210f; border:0; cursor:pointer; }
      .yellow { background:var(--yellow); color:#201a03; border:0; cursor:pointer; }
      .muted { color:#9ca3af; }
      form.inline { display:inline; }
    </style>
  </head>
  <body><div class="wrap">${body}</div></body>
  </html>`;
}

// ---------- routes ----------
app.get("/", (req, res) => {
  if (req.session.userId) return res.redirect("/app");
  res.send(
    layout("Kiwi Sales Counter", `
      <div class="card">
        <h1>Kiwi Sales Counter</h1>
        <p class="muted">Track per-user button presses. Sign up or log in.</p>
        <p><a href="/register">Create account</a> · <a href="/login">Log in</a></p>
      </div>
    `)
  );
});

// auth
app.get("/register", (req, res) => {
  res.send(
    layout("Register", `
      <div class="card">
        <h2>Create account</h2>
        <form method="post" action="/register">
          <div class="space"></div>
          <input name="username" placeholder="Username" required />
          <div class="space"></div>
          <input name="password" type="password" placeholder="Password" required />
          <div class="space"></div>
          <button type="submit">Sign up</button>
          <span class="muted"> &nbsp;Already have an account? <a href="/login">Log in</a></span>
        </form>
      </div>
    `)
  );
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send("Missing fields");
  const normalized = String(username).trim().toLowerCase();
  const hash = await bcrypt.hash(String(password), 12);

  db.run(
    "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
    [uuidv4(), normalized, hash, new Date().toISOString()],
    (err) => {
      if (err) {
        if (String(err.message).includes("UNIQUE")) {
          return res.send(
            layout("Register", `<div class="card"><p>Username already exists. <a href="/login">Log in</a></p></div>`)
          );
        }
        return res.status(500).send("Server error");
      }
      res.redirect("/login");
    }
  );
});

app.get("/login", (req, res) => {
  res.send(
    layout("Login", `
      <div class="card">
        <h2>Log in</h2>
        <form method="post" action="/login">
          <div class="space"></div>
          <input name="username" placeholder="Username" required />
          <div class="space"></div>
          <input name="password" type="password" placeholder="Password" required />
          <div class="space"></div>
          <button type="submit">Log in</button>
          <span class="muted"> &nbsp;No account? <a href="/register">Create one</a></span>
        </form>
      </div>
    `)
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const normalized = String(username || "").trim().toLowerCase();
  db.get("SELECT * FROM users WHERE username = ?", [normalized], async (err, user) => {
    if (err) return res.status(500).send("Server error");
    if (!user) return res.send(layout("Login", `<div class="card"><p>Invalid credentials. <a href="/login">Try again</a></p></div>`));
    const ok = await bcrypt.compare(String(password || ""), user.password_hash);
    if (!ok) return res.send(layout("Login", `<div class="card"><p>Invalid credentials. <a href="/login">Try again</a></p></div>`));
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect("/app");
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// app
app.get("/app", requireAuth, (req, res) => {
  db.get("SELECT username, green_count, yellow_count FROM users WHERE id = ?", [req.session.userId], (err, row) => {
    if (err || !row) return res.status(500).send("Server error");
    const body = `
      <div class="card">
        <div class="actions">
          <h1>Kiwi Sales Counter</h1>
          <form class="inline" method="post" action="/logout"><button>Log out</button></form>
        </div>
        <p class="muted">Hi, <strong>${row.username}</strong> — your counts are saved to your account.</p>

        <div class="btns">
          <form method="post" action="/increment/green">
            <button class="circle green" type="submit">${row.green_count}</button>
          </form>
          <form method="post" action="/increment/yellow">
            <button class="circle yellow" type="submit">${row.yellow_count}</button>
          </form>
        </div>

        <div class="space"></div>
        <form method="post" action="/reset">
          <button type="submit">Reset Counters</button>
        </form>
      </div>`;
    res.send(layout("Your Counters", body));
  });
});

app.post("/increment/green", requireAuth, (req, res) => {
  db.run("UPDATE users SET green_count = green_count + 1 WHERE id = ?", [req.session.userId], (err) => {
    if (err) return res.status(500).send("Server error");
    res.redirect("/app");
  });
});

app.post("/increment/yellow", requireAuth, (req, res) => {
  db.run("UPDATE users SET yellow_count = yellow_count + 1 WHERE id = ?", [req.session.userId], (err) => {
    if (err) return res.status(500).send("Server error");
    res.redirect("/app");
  });
});

app.post("/reset", requireAuth, (req, res) => {
  db.run("UPDATE users SET green_count = 0, yellow_count = 0 WHERE id = ?", [req.session.userId], (err) => {
    if (err) return res.status(500).send("Server error");
    res.redirect("/app");
  });
});

// start
app.listen(PORT, () => {
  console.log(`Kiwi Sales Counter running on http://localhost:${PORT}`);
});
