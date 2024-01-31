// Level 4 - hash

import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import LocalStrategy from "passport-local";
import bcrypt from "bcrypt";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";

const app = express();
const port = 3000;
const saltRounds = 10; // for hashing

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// explanation for resave and saveUninitialized:
// https://stackoverflow.com/questions/40381401/when-to-use-saveuninitialized-and-resave-in-express-session

// basic express session({}) initialization
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DATABASE,
  password: process.env.DB_PASSWORD,
  port: 5432,
});

db.connect();

async function createUser(email, password) {
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    const { rows } = await db.query(
      `INSERT INTO "User" (email, password) VALUES ($1, $2) RETURNING id, email, password`,
      [email, hash]
    );
    return rows[0];
  } catch (err) {
    console.log("Error creating user:", err);
    throw err;
  }
}

async function checkExistence(email) {
  const { rows } = await db.query(
    'SELECT id, email, password FROM "User" WHERE email = $1',
    [email]
  );
  return rows[0];
}

async function validatePassword(password, hashedPassword) {
  const match = await bcrypt.compare(password, hashedPassword);
  return match;
}

// create 'User' table
db.query(`
    CREATE TABLE IF NOT EXISTS "User" (
        id SERIAL PRIMARY KEY,
        email VARCHAR(100) UNIQUE,
        password VARCHAR(100),
        googleId VARCHAR(50),
        facebookId VARCHAR(50),
        secret VARCHAR(100)
    )
`);

// register
passport.use(
  "local-register",
  new LocalStrategy(async (email, password, done) => {
    try {
      const existingUser = await checkExistence(email);
      // email has been registered
      if (existingUser) done(null, false);
      // create a user account
      const user = await createUser(email, password);
      return done(null, user);
    } catch (err) {
      done(err, false);
    }
  })
);

// login
passport.use(
  "local-login",
  new LocalStrategy(async (email, password, done) => {
    try {
      const existingUser = await checkExistence(email);
      // email does not exist
      if (!existingUser) return done(null, false);
      // validate the password
      const match = await validatePassword(password, existingUser.password);
      // the password is wrong
      if (!match) return done(null, false);
      return done(null, existingUser);
    } catch (err) {
      return done(err, false);
    }
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    async (accessToken, refreshToken, profile, done) => {
      const googleId = profile.id;
      const email = profile.emails[0].value;
      console.log(googleId, email);
      try {
        const { rows: existingUser } = await db.query(
          `SELECT id, email, googleId FROM "User" WHERE googleId = $1`,
          [googleId]
        );
        if (existingUser.length) {
          console.log("existing user:", existingUser[0]);
          done(null, existingUser[0]);
        } else {
          const { rows: insertedUser } = await db.query(
            `INSERT INTO "User" (email, googleId)
             VALUES ($1, $2) RETURNING id, email, googleId`,
            [email, googleId]
          );
          console.log("inserted user:", insertedUser);
          done(null, insertedUser[0]);
        }
      } catch (err) {
        console.log("error:", err);
        done(err, false);
      }
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "https://6175-59-102-241-69.ngrok-free.app/auth/facebook/secrets",
    },
    async (accessToken, refreshToken, profile, done) => {
      const facebookId = profile.id;
      const email = profile.emails[0].value;
      console.log(facebookId, email);
      try {
        const { rows: existingUser } = await db.query(
          `SELECT id, email, facebookId FROM "User" WHERE facebookId = $1`,
          [facebookId]
        );
        if (existingUser.length) {
          console.log("existing user:", existingUser[0]);
          done(null, existingUser[0]);
        } else {
          const { rows: insertedUser } = await db.query(
            `INSERT INTO "User" (email, facebookId)
             VALUES ($1, $2) RETURNING id, email, facebookId`,
            [email, facebookId]
          );
          console.log("inserted user:", insertedUser);
          done(null, insertedUser[0]);
        }
      } catch (err) {
        console.log("error:", err);
        done(err, false);
      }
    }
  )
);

// clear explanation for serialization and deserialization:
// https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize

passport.serializeUser((user, done) => {
  console.log("serialize:", user);
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  console.log("deserialize:", id);
  try {
    const { rows } = await db.query('SELECT * FROM "User" WHERE id = $1', [id]);
    const user = rows[0];
    console.log(user);
    done(null, user);
  } catch (err) {
    done(err, false);
  }
});

/// initialize passport on every route call
app.use(passport.initialize());

// allow passport to use 'express-session'
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home");
});

app.get(
  "/auth/google",
  // initiate authentication on Google's servers asking
  // them for the user's profile once they've logged in.
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  // once Google authentication is successful, Google will
  // redirect the user back to our website and make a get request
  // to /auth/google/secrets
  passport.authenticate("google", {
    failureRedirect: "/login",
    successRedirect: "/secrets",
  })
);

app.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["profile", "email"] })
);

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", {
    failureRedirect: "/login",
    successRedirect: "/secrets",
  })
);

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  console.log("GET /register:");
  res.render("register");
});

app.get("/secrets", async (req, res) => {
  try {
    const { rows } = await db.query(`SELECT secret FROM "User" WHERE secret is NOT NULL`);
    if (rows.length) {
      const foundSecrets = rows.map(({ secret }) => secret);
      console.log("secrets:", foundSecrets);
      res.render("secrets", { foundSecrets: foundSecrets });
    }
  } catch (err) {
    console.log("error:", err);
  }  
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  const submittedSecrets = req.body.secret;
  console.log("user id:", req.user.id);
  try {
    await db.query(
      `UPDATE "User" SET secret = $1 WHERE id = $2`,
      [submittedSecrets, req.user.id]
    )
    res.redirect("/secrets");
  } catch (err) {
    console.log("error:", err);
  }
})

app.get("/logout", (req, res) => {
  console.log("/logout");
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.post(
  "/login",
  passport.authenticate("local-login", {
    failureRedirect: "/login", // redirect to /login on login failure
    successRedirect: "/secrets", // redirect to /secrets on login success
  })
);

app.post(
  "/register",
  passport.authenticate("local-register", {
    failureRedirect: "/register", // redirect to /register on register failure
    successRedirect: "/secrets", // redirect to /secrets on register success
  })
);

app.listen(port, () => {
  console.log(`Listening on port ${port}...`);
});
