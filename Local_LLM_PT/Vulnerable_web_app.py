import sqlite3
import os
from flask import Flask, request, redirect, url_for, session, g, render_template_string

app = Flask(__name__)
app.secret_key = "changeme"
DATABASE = "/tmp/app.db"


# ── DB helpers ────────────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db:
        db.close()


def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.executescript("""
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email    TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        );

        DROP TABLE IF EXISTS products;
        CREATE TABLE products (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            category TEXT NOT NULL,
            price    REAL NOT NULL
        );

        DROP TABLE IF EXISTS orders;
        CREATE TABLE orders (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity   INTEGER NOT NULL,
            status     TEXT NOT NULL DEFAULT 'pending'
        );

        INSERT INTO users (username, password, email, role) VALUES
            ('admin',   'admin123',  'admin@corp.local',  'admin'),
            ('alice',   'alice456',  'alice@corp.local',  'user'),
            ('bob',     'bob789',    'bob@corp.local',    'user'),
            ('charlie', 'charlie00', 'charlie@corp.local','user');

        INSERT INTO products (name, category, price) VALUES
            ('Laptop Pro',    'Electronics', 1299.99),
            ('Wireless Mouse','Electronics',   29.99),
            ('Standing Desk', 'Furniture',   499.00),
            ('Monitor 27"',   'Electronics', 349.99),
            ('Keyboard',      'Electronics',  79.99);

        INSERT INTO orders (user_id, product_id, quantity, status) VALUES
            (1, 1, 1, 'delivered'),
            (2, 2, 2, 'shipped'),
            (3, 3, 1, 'pending'),
            (4, 4, 1, 'delivered');
    """)
    conn.commit()
    conn.close()


# ── Shared CSS / layout ───────────────────────────────────────────────────────

BASE_STYLE = """
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', sans-serif;
    min-height: 100vh;
    background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
    color: #fff;
  }
  a { color: inherit; text-decoration: none; }

  /* ── Nav ── */
  nav {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 40px;
    background: rgba(255,255,255,0.04);
    border-bottom: 1px solid rgba(255,255,255,0.08);
    backdrop-filter: blur(10px);
  }
  .nav-brand { font-weight: 700; font-size: 1.1rem; letter-spacing: 0.02em; }
  .nav-links { display: flex; gap: 24px; font-size: 0.9rem; color: rgba(255,255,255,0.6); }
  .nav-links a:hover { color: #fff; }

  /* ── Cards ── */
  .card {
    background: rgba(255,255,255,0.05);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 16px;
    padding: 32px;
  }

  /* ── Form elements ── */
  .form-group { margin-bottom: 18px; }
  label {
    display: block; color: rgba(255,255,255,0.65);
    font-size: 0.78rem; font-weight: 500;
    text-transform: uppercase; letter-spacing: 0.05em;
    margin-bottom: 6px;
  }
  input, select {
    width: 100%; padding: 11px 14px;
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 10px; color: #fff;
    font-size: 0.92rem; font-family: inherit; outline: none;
    transition: border-color .2s, box-shadow .2s;
  }
  input:focus, select:focus {
    border-color: #7c6ef7;
    box-shadow: 0 0 0 3px rgba(124,110,247,.22);
  }
  input::placeholder { color: rgba(255,255,255,0.25); }
  select option { background: #302b63; }

  /* ── Buttons ── */
  .btn {
    display: inline-block; padding: 11px 22px;
    background: linear-gradient(135deg, #7c6ef7, #5a4fcf);
    border: none; border-radius: 10px;
    color: #fff; font-size: 0.92rem; font-weight: 600;
    font-family: inherit; cursor: pointer;
    transition: opacity .2s, transform .1s;
  }
  .btn:hover  { opacity: .88; }
  .btn:active { transform: scale(.97); }
  .btn-ghost {
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.14);
  }
  .btn-ghost:hover { background: rgba(255,255,255,0.15); }

  /* ── Tables ── */
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th {
    text-align: left; padding: 10px 14px;
    color: rgba(255,255,255,0.5);
    font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;
    border-bottom: 1px solid rgba(255,255,255,0.1);
  }
  td { padding: 12px 14px; border-bottom: 1px solid rgba(255,255,255,0.06); }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.03); }

  /* ── Misc ── */
  .page { max-width: 960px; margin: 0 auto; padding: 40px 20px; }
  .page-title { font-size: 1.5rem; font-weight: 700; margin-bottom: 24px; }
  .alert-error {
    background: rgba(239,68,68,.15);
    border: 1px solid rgba(239,68,68,.35);
    color: #fca5a5; border-radius: 10px;
    padding: 10px 14px; font-size: .875rem;
    margin-bottom: 18px; text-align: center;
  }
  .badge {
    display: inline-block; padding: 3px 10px;
    border-radius: 20px; font-size: 0.75rem; font-weight: 600;
  }
  .badge-green  { background: rgba(34,197,94,.2);  color: #86efac; }
  .badge-yellow { background: rgba(234,179,8,.2);  color: #fde047; }
  .badge-blue   { background: rgba(59,130,246,.2); color: #93c5fd; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media(max-width:640px){ .grid-2 { grid-template-columns: 1fr; } }
</style>
"""

NAV = """
<nav>
  <span class="nav-brand">&#9670; CorpPortal</span>
  <div class="nav-links">
    <a href="/dashboard">Home</a>
    <a href="/products">Products</a>
    <a href="/users">Users</a>
    <a href="/orders">Orders</a>
    <a href="/logout">Sign out</a>
  </div>
</nav>
"""


# ── Templates ─────────────────────────────────────────────────────────────────

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Sign In – CorpPortal</title>
  """ + BASE_STYLE + """
  <style>
    body { display:flex; align-items:center; justify-content:center; }
    .login-wrap { width:100%; max-width:420px; }
    .logo { text-align:center; margin-bottom:28px; }
    .logo svg { width:52px; height:52px; }
    h1 { text-align:center; font-size:1.55rem; margin-bottom:6px; }
    .sub { text-align:center; color:rgba(255,255,255,.45); font-size:.875rem; margin-bottom:32px; }
  </style>
</head>
<body>
  <div class="login-wrap">
    <div class="logo">
      <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="24" cy="24" r="24" fill="url(#lg)"/>
        <path d="M16 20v-2a8 8 0 0116 0v2" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/>
        <rect x="12" y="20" width="24" height="16" rx="4" fill="#fff" fill-opacity=".15" stroke="#fff" stroke-width="2"/>
        <circle cx="24" cy="28" r="2.5" fill="#fff"/>
        <defs>
          <linearGradient id="lg" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
            <stop stop-color="#7c6ef7"/><stop offset="1" stop-color="#5a4fcf"/>
          </linearGradient>
        </defs>
      </svg>
    </div>
    <div class="card">
      <h1>Welcome back</h1>
      <p class="sub">Sign in to your account to continue</p>
      {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
      <form method="POST" action="/login">
        <div class="form-group">
          <label for="username">Username</label>
          <input id="username" name="username" type="text" placeholder="Enter your username" autocomplete="off" required/>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input id="password" name="password" type="password" placeholder="Enter your password" required/>
        </div>
        <button class="btn" style="width:100%;margin-top:4px" type="submit">Sign In</button>
      </form>
    </div>
  </div>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Dashboard – CorpPortal</title>
  """ + BASE_STYLE + """
</head>
<body>
  """ + NAV + """
  <div class="page">
    <p class="page-title">Dashboard</p>
    <div class="grid-2">
      <div class="card" style="text-align:center;padding:40px">
        <div style="font-size:2.5rem;font-weight:700;color:#a78bfa">{{ user_count }}</div>
        <div style="color:rgba(255,255,255,.5);margin-top:6px">Registered Users</div>
      </div>
      <div class="card" style="text-align:center;padding:40px">
        <div style="font-size:2.5rem;font-weight:700;color:#a78bfa">{{ product_count }}</div>
        <div style="color:rgba(255,255,255,.5);margin-top:6px">Products</div>
      </div>
    </div>
    <div class="card" style="margin-top:24px">
      <p style="color:rgba(255,255,255,.55)">Logged in as <strong>{{ username }}</strong>. Use the navigation above to explore the portal.</p>
    </div>
  </div>
</body>
</html>
"""

USERS_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Users – CorpPortal</title>
  """ + BASE_STYLE + """
</head>
<body>
  """ + NAV + """
  <div class="page">
    <p class="page-title">User Directory</p>
    <div class="card" style="margin-bottom:24px">
      <form method="GET" action="/users" style="display:flex;gap:12px;align-items:flex-end">
        <div class="form-group" style="flex:1;margin:0">
          <label for="q">Search by name</label>
          <input id="q" name="q" type="text" placeholder="e.g. alice" value="{{ query }}"/>
        </div>
        <button class="btn" type="submit">Search</button>
      </form>
    </div>
    {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
    <div class="card">
      <table>
        <thead><tr><th>#</th><th>Username</th><th>Email</th><th>Role</th><th></th></tr></thead>
        <tbody>
          {% for u in users %}
          <tr>
            <td style="color:rgba(255,255,255,.4)">{{ u.id }}</td>
            <td>{{ u.username }}</td>
            <td style="color:rgba(255,255,255,.6)">{{ u.email }}</td>
            <td>
              {% if u.role == 'admin' %}
                <span class="badge badge-blue">admin</span>
              {% else %}
                <span class="badge badge-green">user</span>
              {% endif %}
            </td>
            <td><a href="/profile/{{ u.id }}" class="btn btn-ghost" style="padding:6px 14px;font-size:.8rem">View</a></td>
          </tr>
          {% else %}
          <tr><td colspan="5" style="text-align:center;color:rgba(255,255,255,.35);padding:28px">No users found.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""

PROFILE_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Profile – CorpPortal</title>
  """ + BASE_STYLE + """
</head>
<body>
  """ + NAV + """
  <div class="page" style="max-width:560px">
    <p class="page-title">User Profile</p>
    {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
    {% if user %}
    <div class="card">
      <table>
        <tr><th>ID</th><td>{{ user.id }}</td></tr>
        <tr><th>Username</th><td>{{ user.username }}</td></tr>
        <tr><th>Email</th><td>{{ user.email }}</td></tr>
        <tr><th>Role</th><td>{{ user.role }}</td></tr>
      </table>
    </div>
    {% endif %}
  </div>
</body>
</html>
"""

PRODUCTS_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Products – CorpPortal</title>
  """ + BASE_STYLE + """
</head>
<body>
  """ + NAV + """
  <div class="page">
    <p class="page-title">Product Catalogue</p>
    <div class="card" style="margin-bottom:24px">
      <form method="GET" action="/products" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
        <div class="form-group" style="flex:1;margin:0;min-width:160px">
          <label for="category">Category</label>
          <input id="category" name="category" type="text" placeholder="e.g. Electronics" value="{{ category }}"/>
        </div>
        <div class="form-group" style="flex:1;margin:0;min-width:160px">
          <label for="sort">Sort by</label>
          <select id="sort" name="sort">
            <option value="name" {% if sort=='name' %}selected{% endif %}>Name</option>
            <option value="price" {% if sort=='price' %}selected{% endif %}>Price</option>
          </select>
        </div>
        <button class="btn" type="submit">Apply</button>
      </form>
    </div>
    {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
    <div class="card">
      <table>
        <thead><tr><th>#</th><th>Name</th><th>Category</th><th>Price</th></tr></thead>
        <tbody>
          {% for p in products %}
          <tr>
            <td style="color:rgba(255,255,255,.4)">{{ p.id }}</td>
            <td>{{ p.name }}</td>
            <td><span class="badge badge-yellow">{{ p.category }}</span></td>
            <td>${{ "%.2f"|format(p.price) }}</td>
          </tr>
          {% else %}
          <tr><td colspan="4" style="text-align:center;color:rgba(255,255,255,.35);padding:28px">No products found.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""

ORDERS_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Orders – CorpPortal</title>
  """ + BASE_STYLE + """
</head>
<body>
  """ + NAV + """
  <div class="page">
    <p class="page-title">Order History</p>
    <div class="card" style="margin-bottom:24px">
      <form method="GET" action="/orders" style="display:flex;gap:12px;align-items:flex-end">
        <div class="form-group" style="flex:1;margin:0">
          <label for="status">Filter by status</label>
          <input id="status" name="status" type="text" placeholder="e.g. pending" value="{{ status }}"/>
        </div>
        <button class="btn" type="submit">Filter</button>
      </form>
    </div>
    {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
    <div class="card">
      <table>
        <thead><tr><th>Order #</th><th>User</th><th>Product</th><th>Qty</th><th>Status</th></tr></thead>
        <tbody>
          {% for o in orders %}
          <tr>
            <td style="color:rgba(255,255,255,.4)">{{ o.id }}</td>
            <td>{{ o.username }}</td>
            <td>{{ o.product_name }}</td>
            <td>{{ o.quantity }}</td>
            <td>
              {% if o.status == 'delivered' %}
                <span class="badge badge-green">delivered</span>
              {% elif o.status == 'shipped' %}
                <span class="badge badge-blue">shipped</span>
              {% else %}
                <span class="badge badge-yellow">{{ o.status }}</span>
              {% endif %}
            </td>
          </tr>
          {% else %}
          <tr><td colspan="5" style="text-align:center;color:rgba(255,255,255,.35);padding:28px">No orders found.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""


# ── Routes ────────────────────────────────────────────────────────────────────

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


@app.route("/", methods=["GET"])
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        row = db.execute(query).fetchone()
    except Exception:
        return render_template_string(LOGIN_PAGE, error="An error occurred. Please try again."), 500
    if row:
        session["username"] = row["username"]
        return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_PAGE, error="Invalid username or password."), 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user_count    = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    product_count = db.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    return render_template_string(
        DASHBOARD_PAGE,
        username=session["username"],
        user_count=user_count,
        product_count=product_count,
    )


@app.route("/users")
@login_required
def users():
    q  = request.args.get("q", "")
    db = get_db()
    if q:
        query = f"SELECT * FROM users WHERE username LIKE '%{q}%'"
    else:
        query = "SELECT * FROM users"
    try:
        rows = [dict(r) for r in db.execute(query).fetchall()]
        err  = None
    except Exception:
        rows = []
        err  = "An error occurred while fetching users."
    return render_template_string(USERS_PAGE, users=rows, query=q, error=err)


@app.route("/profile/<user_id>")
@login_required
def profile(user_id):
    db    = get_db()
    query = "SELECT id, username, email, role FROM users WHERE id = " + user_id
    try:
        row = db.execute(query).fetchone()
        err = None
    except Exception:
        row = None
        err = "An error occurred while loading the profile."
    return render_template_string(
        PROFILE_PAGE,
        user=dict(row) if row else None,
        error=err,
    )


@app.route("/products")
@login_required
def products():
    category = request.args.get("category", "")
    sort     = request.args.get("sort", "name")
    db       = get_db()
    if category:
        query = f"SELECT * FROM products WHERE category = '{category}' ORDER BY {sort}"
    else:
        query = f"SELECT * FROM products ORDER BY {sort}"
    try:
        rows = [dict(r) for r in db.execute(query).fetchall()]
        err  = None
    except Exception:
        rows = []
        err  = "An error occurred while loading products."
    return render_template_string(
        PRODUCTS_PAGE,
        products=rows,
        category=category,
        sort=sort,
        error=err,
    )


@app.route("/orders")
@login_required
def orders():
    status = request.args.get("status", "")
    db     = get_db()
    base   = """
        SELECT o.id, u.username, p.name AS product_name, o.quantity, o.status
        FROM orders o
        JOIN users    u ON u.id = o.user_id
        JOIN products p ON p.id = o.product_id
    """
    if status:
        query = base + f" WHERE o.status = '{status}'"
    else:
        query = base
    try:
        rows = [dict(r) for r in db.execute(query).fetchall()]
        err  = None
    except Exception:
        rows = []
        err  = "An error occurred while loading orders."
    return render_template_string(ORDERS_PAGE, orders=rows, status=status, error=err)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not os.path.exists(DATABASE) or os.path.getsize(DATABASE) == 0:
        init_db()
    app.run(debug=True, host="0.0.0.0", port=5001)
