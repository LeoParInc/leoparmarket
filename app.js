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

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price REAL,
    image TEXT,
    seller TEXT
  )`);
});

// helper middleware
function checkAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

function checkAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  res.status(403).send('admin only');
}

// Routes

// home
app.get('/', (req, res) => {
  res.send('welcome to LeoPar Marketplace!');
});

// Register
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

// Login
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

// Admin dashboard - list products + add new product form
app.get('/admin/dashboard', checkAdmin, (req, res) => {
  db.all(`SELECT * FROM products`, [], (err, products) => {
    if (err) return res.send('db error');
    let list = products.map(p => `
      <li>
        <b>${p.name}</b> - ${p.price}₺ - Seller: ${p.seller}
        <a href="/admin/products/edit/${p.id}">Edit</a>
      </li>
    `).join('');
    res.send(`
      <h1>Admin Dashboard</h1>
      <h2>Products</h2>
      <ul>${list}</ul>
      <h2>Add New Product</h2>
      <form method="POST" action="/admin/products/new">
        <input name="name" placeholder="Name" required><br>
        <textarea name="description" placeholder="Description"></textarea><br>
        <input name="price" type="number" step="0.01" placeholder="Price" required><br>
        <input name="image" placeholder="Image URL"><br>
        <input name="seller" placeholder="Seller"><br>
        <button type="submit">Create</button>
      </form>
      <a href="/logout">Logout</a>
    `);
  });
});

// Create new product
app.post('/admin/products/new', checkAdmin, (req, res) => {
  const { name, description, price, image, seller } = req.body;
  db.run(`INSERT INTO products (name, description, price, image, seller) VALUES (?, ?, ?, ?, ?)`,
    [name, description, price, image, seller], err => {
      if (err) return res.send('db error on insert');
      res.redirect('/admin/dashboard');
    });
});

// Edit product page
app.get('/admin/products/edit/:id', checkAdmin, (req, res) => {
  const id = req.params.id;
  db.get(`SELECT * FROM products WHERE id = ?`, [id], (err, product) => {
    if (err || !product) return res.send('product not found');
    res.send(`
      <h1>Edit Product</h1>
      <form method="POST" action="/admin/products/edit/${id}">
        <input name="name" value="${product.name}" required><br>
        <textarea name="description">${product.description}</textarea><br>
        <input name="price" type="number" step="0.01" value="${product.price}" required><br>
        <input name="image" value="${product.image}"><br>
        <input name="seller" value="${product.seller}"><br>
        <button type="submit">Save</button>
      </form>
      <a href="/admin/dashboard">Back</a>
    `);
  });
});

// Save edited product
app.post('/admin/products/edit/:id', checkAdmin, (req, res) => {
  const id = req.params.id;
  const { name, description, price, image, seller } = req.body;
  db.run(`UPDATE products SET name = ?, description = ?, price = ?, image = ?, seller = ? WHERE id = ?`,
    [name, description, price, image, seller, id], err => {
      if (err) return res.send('db error on update');
      res.redirect('/admin/dashboard');
    });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`LeoPar server running on http://localhost:${PORT}`);
});
