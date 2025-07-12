const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database('./data/db.sqlite');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(session({
  secret: 'leopar-secret-key',
  resave: false,
  saveUninitialized: false,
}));

// init tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    username TEXT,
    password TEXT,
    is_admin INTEGER DEFAULT 0
  )`);
});

// helper: check auth
function checkAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

function checkAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  res.status(403).send('admin only');
}

// Routes
app.get('/', (req, res) => {
  res.send('welcome to LeoPar Marketplace!');
});

// Register page
app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/public/register.html');
});

app.post('/register', (req, res) => {
  const { email, username, password } = req.body;
  const hash = bcrypt.hashSync(password, 8);
  db.run(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, [email, username, hash], function(err) {
    if (err) return res.send('email already used');
    req.session.userId = this.lastID;
    req.session.isAdmin = 0;
    res.redirect('/');
  });
});

// Login page
app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err || !user) return res.send('invalid credentials');
    if (!bcrypt.compareSync(password, user.password)) return res.send('invalid credentials');
    req.session.userId = user.id;
    req.session.isAdmin = user.is_admin === 1;
    res.redirect('/');
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Admin Dashboard (example protected)
app.get('/admin', checkAdmin, (req, res) => {
  res.send('admin dashboard (protected)');
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`LeoPar server running on http://localhost:${PORT}`);
});
