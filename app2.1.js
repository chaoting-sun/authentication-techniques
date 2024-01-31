// Level 2 - .env file
// use nodemon --env-file=.env app3.js
// source: https://medium.com/@tony.infisical/stop-using-dotenv-in-node-js-v20-6-0-8febf98f6314

import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import crypto from "crypto";

const app = express();
const port = 3000;

console.log(process.env.KEY);

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

// use encrypt and decript function on password

// get the value of key and iv and past them in the .env
// const key = crypto.randomBytes(32).toString('hex');
// const iv = crypto.randomBytes(16).toString('hex');

const algorithm = "aes-256-cbc";
const key = Buffer.from(process.env.CRYPTO_KEY, 'hex');
const iv = Buffer.from(process.env.CRYPTO_IV, 'hex');

function encrypt(data) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(data, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

function decrypt(encryptedData) {
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
  decrypted += decipher.final('utf-8');
  return decrypted;
}

async function createUser(email, password) {
  const encryptedPassword = encrypt(password);
  await db.query('INSERT INTO "User" (email, password) VALUES ($1, $2)', [
    email,
    encryptedPassword,
  ]);
}

async function validateUser(email, password) {
  const { rows } = await db.query(
    'SELECT password FROM "User" WHERE email = $1',
    [email]
  );
  const encrytedPassword = rows[0].password;
  const decrytedPassword = decrypt(encrytedPassword);
  return password === decrytedPassword;
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
    console.log("error:", err);
  }
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  if (validateUser(username, password)) {
    res.render("secrets");
  } else {
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}...`);
});
