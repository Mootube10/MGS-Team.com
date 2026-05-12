// server.js
// Nexus Control Backend (Single File)
// Run:
// npm install express cors dotenv bcrypt jsonwebtoken express-session passport passport-discord stripe sqlite3
// node server.js

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const Stripe = require("stripe");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = process.env.PORT || 3000;

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// =========================
// DATABASE
// =========================

const db = new sqlite3.Database("./nexus.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      email TEXT UNIQUE,
      password TEXT,
      discordId TEXT,
      avatar TEXT,
      plan TEXT DEFAULT 'free',
      role TEXT DEFAULT 'owner',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      stripeCustomerId TEXT,
      stripeSubscriptionId TEXT,
      status TEXT,
      plan TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// =========================
// MIDDLEWARE
// =========================

app.use(cors());
app.use(express.json());

app.use(
  session({
    secret: "nexus_secret",
    resave: false,
    saveUninitialized: false
  })
);

app.use(passport.initialize());
app.use(passport.session());

// =========================
// JWT AUTH
// =========================

function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    "super_secret_jwt",
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({
      error: "No token provided"
    });
  }

  try {
    const decoded = jwt.verify(token, "super_secret_jwt");
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid token"
    });
  }
}

// =========================
// DISCORD AUTH
// =========================

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

passport.use(
  new DiscordStrategy(
    {
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/discord/callback",
      scope: ["identify", "email"]
    },
    async (accessToken, refreshToken, profile, done) => {
      db.get(
        "SELECT * FROM users WHERE discordId = ?",
        [profile.id],
        (err, user) => {
          if (user) {
            return done(null, user);
          }

          db.run(
            `
            INSERT INTO users 
            (username, email, discordId, avatar)
            VALUES (?, ?, ?, ?)
          `,
            [
              profile.username,
              profile.email,
              profile.id,
              profile.avatar
            ],
            function () {
              db.get(
                "SELECT * FROM users WHERE id = ?",
                [this.lastID],
                (err, newUser) => {
                  done(null, newUser);
                }
              );
            }
          );
        }
      );
    }
  )
);

// =========================
// ROUTES
// =========================

app.get("/", (req, res) => {
  res.json({
    message: "Nexus Control Backend Running"
  });
});

// =========================
// REGISTER
// =========================

app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({
      error: "All fields required"
    });
  }

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    `
    INSERT INTO users (username, email, password)
    VALUES (?, ?, ?)
  `,
    [username, email, hashed],
    function (err) {
      if (err) {
        return res.status(400).json({
          error: "Email already exists"
        });
      }

      const token = generateToken({
        id: this.lastID,
        email,
        role: "owner"
      });

      res.json({
        success: true,
        token
      });
    }
  );
});

// =========================
// LOGIN
// =========================

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, user) => {
      if (!user) {
        return res.status(400).json({
          error: "User not found"
        });
      }

      const valid = await bcrypt.compare(password, user.password);

      if (!valid) {
        return res.status(400).json({
          error: "Invalid password"
        });
      }

      const token = generateToken(user);

      res.json({
        success: true,
        token,
        user
      });
    }
  );
});

// =========================
// DISCORD LOGIN
// =========================

app.get(
  "/auth/discord",
  passport.authenticate("discord")
);

app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", {
    failureRedirect: "/login"
  }),
  (req, res) => {
    const token = generateToken(req.user);

    res.redirect(
      `http://localhost:5500/dashboard.html?token=${token}`
    );
  }
);

// =========================
// GET USER
// =========================

app.get("/api/me", auth, (req, res) => {
  db.get(
    "SELECT * FROM users WHERE id = ?",
    [req.user.id],
    (err, user) => {
      res.json(user);
    }
  );
});

// =========================
// CREATE STRIPE CHECKOUT
// =========================

app.post("/api/create-checkout", auth, async (req, res) => {
  const { plan } = req.body;

  let price = 0;

  if (plan === "pro") {
    price = 1499;
  }

  if (plan === "enterprise") {
    price = 4999;
  }

  if (price === 0) {
    return res.json({
      free: true
    });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],

      line_items: [
        {
          price_data: {
            currency: "gbp",
            product_data: {
              name: `Nexus ${plan}`
            },
            unit_amount: price,
            recurring: {
              interval: "month"
            }
          },
          quantity: 1
        }
      ],

      mode: "subscription",

      success_url:
        "http://localhost:5500/dashboard.html?success=true",

      cancel_url:
        "http://localhost:5500/pricing.html?cancelled=true"
    });

    res.json({
      url: session.url
    });
  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

// =========================
// UPDATE PLAN
// =========================

app.post("/api/update-plan", auth, (req, res) => {
  const { plan } = req.body;

  db.run(
    "UPDATE users SET plan = ? WHERE id = ?",
    [plan, req.user.id],
    function () {
      res.json({
        success: true
      });
    }
  );
});

// =========================
// DASHBOARD DATA
// =========================

app.get("/api/dashboard", auth, (req, res) => {
  res.json({
    totalStaff: 7,
    activeShifts: 2,
    pendingApps: 5,
    openReports: 3,
    totalHours: 84
  });
});

// =========================
// STAFF LIST
// =========================

app.get("/api/staff", auth, (req, res) => {
  db.all(
    "SELECT id, username, email, role, plan FROM users",
    [],
    (err, rows) => {
      res.json(rows);
    }
  );
});

// =========================
// CREATE ANNOUNCEMENT
// =========================

app.post("/api/announcement", auth, (req, res) => {
  const { title, content } = req.body;

  res.json({
    success: true,
    message: "Announcement created",
    announcement: {
      title,
      content
    }
  });
});

// =========================
// LOGOUT
// =========================

app.post("/api/logout", (req, res) => {
  req.logout(() => {
    res.json({
      success: true
    });
  });
});

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {
  console.log(`Nexus backend running on port ${PORT}`);
});
