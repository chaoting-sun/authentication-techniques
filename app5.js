// Level 4 - hash

import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import LocalStrategy from "passport-local";
import bcrypt from "bcrypt";

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

/// initialize passport on every route call
app.use(passport.initialize());

// allow passport to use 'express-session'
app.use(passport.session());

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
        password VARCHAR(100)
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

// clear explanation for serialization and deserialization:
// https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize

passport.serializeUser((user, done) => {
  console.log("serialize:", user);
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await db.query('SELECT * FROM "User" WHERE id = $1', [id]);
    const user = rows[0];
    console.log("deserialize:", user);
    done(null, user);
  } catch (err) {
    done(err, false);
  }
});

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  console.log("GET /register:", req.session, req.sessionID);
  res.render("register");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/local");
  }
});

app.get("/logout", (req, res) => {
  console.log("is authenticated:", req.isAuthenticated());
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
