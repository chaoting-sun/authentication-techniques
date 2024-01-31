// Level 4 - hash

import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10; // for hashing

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DATABASE,
  password: process.env.DB_PASSWORD,
  port: 5432,
});

db.connect();

// create 'User' table
db.query(`
    CREATE TABLE IF NOT EXISTS "User" (
        id SERIAL PRIMARY KEY,
        email VARCHAR(100) UNIQUE,
        password VARCHAR(100)
    )
`);

async function createUser(email, password) {
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    await db.query('INSERT INTO "User" (email, password) VALUES ($1, $2)', [
      email,
      hash,
    ]);
  } catch (err) {
    console.log("Error creating user:", err);
    throw err;
  }
}

async function validateUser(email, password) {
  const { rows } = await db.query(
    'SELECT password FROM "User" WHERE email = $1',
    [email]
  );
  try {
    const hash = rows[0].password;
    const match = await bcrypt.compare(password, hash);
    return match;
  } catch (err) {
    console.log("Error when checking password:", err);
    throw err;
  }
}

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {

  const username = req.body.username;
  const password = req.body.password;
  try {
    await createUser(username, password);
    res.render("secrets");
  } catch (err) {
    console.log("Error in registration route:", err);
    res.sendStatus(500); // internal server error
  }
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const foundUser = await validateUser(username, password);
  if (foundUser) {
    res.render("secrets");
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}...`);
});
