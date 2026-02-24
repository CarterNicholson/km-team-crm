const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const https = require('https');

// ─── Password hashing using built-in crypto (no bcrypt dependency) ────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  return hash === test;
}

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'km-crm-dev-secret-CHANGE-IN-PRODUCTION';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'crm.db');

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════════════════════════════════════
// DATABASE SETUP
// ═══════════════════════════════════════════════════════════════════════════════
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'broker',
    claude_api_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT,
    industry TEXT,
    website TEXT,
    phone TEXT,
    address TEXT,
    city TEXT,
    state TEXT DEFAULT 'WA',
    submarket TEXT,
    notes TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT,
    company_id INTEGER REFERENCES companies(id),
    email TEXT,
    phone TEXT,
    tags TEXT DEFAULT '',
    submarket TEXT,
    size_requirement TEXT,
    industry TEXT,
    notes TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    address TEXT NOT NULL,
    city TEXT,
    state TEXT DEFAULT 'WA',
    submarket TEXT,
    type TEXT DEFAULT 'industrial',
    size_sf INTEGER,
    asking_rate TEXT,
    rate_type TEXT DEFAULT 'NNN',
    status TEXT DEFAULT 'available',
    is_listing INTEGER DEFAULT 0,
    list_date TEXT,
    expiration_date TEXT,
    listing_broker_id INTEGER REFERENCES users(id),
    commission_rate TEXT,
    marketing_notes TEXT,
    clear_height TEXT,
    dock_doors INTEGER,
    notes TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS deals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    stage TEXT DEFAULT 'prospect',
    deal_type TEXT DEFAULT 'lease_tenant',
    contact_id INTEGER REFERENCES contacts(id),
    property_id INTEGER REFERENCES properties(id),
    value TEXT,
    size_sf TEXT,
    close_date TEXT,
    notes TEXT,
    assigned_to INTEGER REFERENCES users(id),
    created_by INTEGER REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    due_date TEXT,
    completed INTEGER DEFAULT 0,
    priority TEXT DEFAULT 'medium',
    contact_id INTEGER,
    deal_id INTEGER,
    property_id INTEGER,
    assigned_to INTEGER REFERENCES users(id),
    notes TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS inquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL REFERENCES properties(id),
    contact_id INTEGER NOT NULL REFERENCES contacts(id),
    status TEXT DEFAULT 'new',
    interest_level TEXT DEFAULT 'medium',
    size_need TEXT,
    notes TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER,
    entity_name TEXT,
    details TEXT,
    user_id INTEGER REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function logActivity(action, entityType, entityId, entityName, details, userId) {
  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, entity_name, details, user_id) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(action, entityType, entityId, entityName, details || null, userId);
}

function now() {
  return new Date().toISOString();
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/auth/status', (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as c FROM users').get();
  res.json({ hasUsers: count.c > 0 });
});

app.post('/api/auth/setup', (req, res) => {
  const existing = db.prepare('SELECT COUNT(*) as c FROM users').get();
  if (existing.c > 0) return res.status(400).json({ error: 'Setup already completed' });
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = hashPassword(password);
  const result = db.prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)').run(name, email, hash, 'admin');
  const user = { id: result.lastInsertRowid, name, email, role: 'admin' };
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
  logActivity('create', 'user', user.id, name, 'Initial admin setup', user.id);
  res.json({ token, user });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
  logActivity('login', 'user', user.id, user.name, null, user.id);
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.get('/api/auth/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT id, name, email, role, claude_api_key FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ ...user, hasApiKey: !!user.claude_api_key });
});

// ═══════════════════════════════════════════════════════════════════════════════
// USER ROUTES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/users', authenticate, (req, res) => {
  res.json(db.prepare('SELECT id, name, email, role, created_at FROM users ORDER BY name').all());
});

app.post('/api/users', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password required' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
    return res.status(400).json({ error: 'Email already in use' });
  }
  const hash = hashPassword(password);
  const result = db.prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)').run(name, email, hash, role || 'broker');
  const user = db.prepare('SELECT id, name, email, role FROM users WHERE id = ?').get(result.lastInsertRowid);
  logActivity('create', 'user', user.id, name, `New team member added (${role || 'broker'})`, req.user.id);
  res.json(user);
});

app.put('/api/users/:id', authenticate, (req, res) => {
  const id = parseInt(req.params.id);
  if (req.user.id !== id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const { name, email, claude_api_key } = req.body;
  db.prepare('UPDATE users SET name = COALESCE(?, name), email = COALESCE(?, email), claude_api_key = ? WHERE id = ?')
    .run(name, email, claude_api_key !== undefined ? claude_api_key : null, id);
  const user = db.prepare('SELECT id, name, email, role, claude_api_key FROM users WHERE id = ?').get(id);
  res.json({ ...user, hasApiKey: !!user.claude_api_key });
});

app.put('/api/users/:id/password', authenticate, (req, res) => {
  const id = parseInt(req.params.id);
  if (req.user.id !== id) return res.status(403).json({ error: 'Forbidden' });
  const { current_password, new_password } = req.body;
  if (!new_password || new_password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!verifyPassword(current_password, user.password_hash)) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(new_password), id);
  res.json({ success: true });
});

app.delete('/api/users/:id', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (req.user.id === parseInt(req.params.id)) return res.status(400).json({ error: 'Cannot delete yourself' });
  const u = db.prepare('SELECT name FROM users WHERE id = ?').get(req.params.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  logActivity('delete', 'user', parseInt(req.params.id), u?.name, 'Team member removed', req.user.id);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// COMPANIES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/companies', authenticate, (req, res) => {
  const rows = db.prepare(`
    SELECT c.*, u.name as created_by_name,
    (SELECT COUNT(*) FROM contacts WHERE company_id = c.id) as contact_count
    FROM companies c LEFT JOIN users u ON c.created_by = u.id
    ORDER BY c.name
  `).all();
  res.json(rows);
});

app.post('/api/companies', authenticate, (req, res) => {
  const { name, type, industry, website, phone, address, city, state, submarket, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'Company name required' });
  const result = db.prepare(
    'INSERT INTO companies (name, type, industry, website, phone, address, city, state, submarket, notes, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
  ).run(name, type, industry, website, phone, address, city, state || 'WA', submarket, notes, req.user.id);
  const row = db.prepare('SELECT * FROM companies WHERE id = ?').get(result.lastInsertRowid);
  logActivity('create', 'company', row.id, name, null, req.user.id);
  res.json(row);
});

app.put('/api/companies/:id', authenticate, (req, res) => {
  const { name, type, industry, website, phone, address, city, state, submarket, notes } = req.body;
  db.prepare(
    'UPDATE companies SET name=?, type=?, industry=?, website=?, phone=?, address=?, city=?, state=?, submarket=?, notes=?, updated_at=? WHERE id=?'
  ).run(name, type, industry, website, phone, address, city, state, submarket, notes, now(), req.params.id);
  const row = db.prepare('SELECT * FROM companies WHERE id = ?').get(req.params.id);
  logActivity('update', 'company', row.id, row.name, null, req.user.id);
  res.json(row);
});

app.delete('/api/companies/:id', authenticate, (req, res) => {
  const c = db.prepare('SELECT name FROM companies WHERE id = ?').get(req.params.id);
  db.prepare('UPDATE contacts SET company_id = NULL WHERE company_id = ?').run(req.params.id);
  db.prepare('DELETE FROM companies WHERE id = ?').run(req.params.id);
  logActivity('delete', 'company', parseInt(req.params.id), c?.name, null, req.user.id);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CONTACTS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/contacts', authenticate, (req, res) => {
  const rows = db.prepare(`
    SELECT c.*, co.name as company_name, u.name as created_by_name
    FROM contacts c
    LEFT JOIN companies co ON c.company_id = co.id
    LEFT JOIN users u ON c.created_by = u.id
    ORDER BY c.first_name, c.last_name
  `).all();
  res.json(rows);
});

app.get('/api/contacts/:id', authenticate, (req, res) => {
  const c = db.prepare(`
    SELECT c.*, co.name as company_name FROM contacts c
    LEFT JOIN companies co ON c.company_id = co.id WHERE c.id = ?
  `).get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Contact not found' });
  const deals = db.prepare('SELECT * FROM deals WHERE contact_id = ? ORDER BY created_at DESC').all(req.params.id);
  const tasks = db.prepare('SELECT * FROM tasks WHERE contact_id = ? ORDER BY due_date').all(req.params.id);
  const inquiries = db.prepare(`
    SELECT i.*, p.address as property_address, p.name as property_name
    FROM inquiries i LEFT JOIN properties p ON i.property_id = p.id
    WHERE i.contact_id = ? ORDER BY i.created_at DESC
  `).all(req.params.id);
  res.json({ ...c, deals, tasks, inquiries });
});

app.post('/api/contacts', authenticate, (req, res) => {
  const { first_name, last_name, company_id, email, phone, tags, submarket, size_requirement, industry, notes } = req.body;
  if (!first_name) return res.status(400).json({ error: 'First name required' });
  const result = db.prepare(
    'INSERT INTO contacts (first_name, last_name, company_id, email, phone, tags, submarket, size_requirement, industry, notes, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
  ).run(first_name, last_name, company_id || null, email, phone, tags || '', submarket, size_requirement, industry, notes, req.user.id);
  const row = db.prepare('SELECT * FROM contacts WHERE id = ?').get(result.lastInsertRowid);
  logActivity('create', 'contact', row.id, `${first_name} ${last_name || ''}`.trim(), null, req.user.id);
  res.json(row);
});

app.put('/api/contacts/:id', authenticate, (req, res) => {
  const { first_name, last_name, company_id, email, phone, tags, submarket, size_requirement, industry, notes } = req.body;
  db.prepare(
    'UPDATE contacts SET first_name=?, last_name=?, company_id=?, email=?, phone=?, tags=?, submarket=?, size_requirement=?, industry=?, notes=?, updated_at=? WHERE id=?'
  ).run(first_name, last_name, company_id || null, email, phone, tags || '', submarket, size_requirement, industry, notes, now(), req.params.id);
  const row = db.prepare('SELECT * FROM contacts WHERE id = ?').get(req.params.id);
  logActivity('update', 'contact', row.id, `${row.first_name} ${row.last_name || ''}`.trim(), null, req.user.id);
  res.json(row);
});

app.delete('/api/contacts/:id', authenticate, (req, res) => {
  const c = db.prepare('SELECT first_name, last_name FROM contacts WHERE id = ?').get(req.params.id);
  db.prepare('DELETE FROM contacts WHERE id = ?').run(req.params.id);
  logActivity('delete', 'contact', parseInt(req.params.id), `${c?.first_name} ${c?.last_name || ''}`.trim(), null, req.user.id);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/properties', authenticate, (req, res) => {
  const rows = db.prepare(`
    SELECT p.*, u.name as listing_broker_name, u2.name as created_by_name,
    (SELECT COUNT(*) FROM inquiries WHERE property_id = p.id) as inquiry_count,
    (SELECT COUNT(*) FROM deals WHERE property_id = p.id) as deal_count
    FROM properties p
    LEFT JOIN users u ON p.listing_broker_id = u.id
    LEFT JOIN users u2 ON p.created_by = u2.id
    ORDER BY p.created_at DESC
  `).all();
  res.json(rows);
});

app.get('/api/properties/listings', authenticate, (req, res) => {
  const rows = db.prepare(`
    SELECT p.*, u.name as listing_broker_name,
    (SELECT COUNT(*) FROM inquiries WHERE property_id = p.id) as inquiry_count,
    (SELECT COUNT(*) FROM deals WHERE property_id = p.id) as deal_count
    FROM properties p
    LEFT JOIN users u ON p.listing_broker_id = u.id
    WHERE p.is_listing = 1
    ORDER BY p.list_date DESC
  `).all();
  res.json(rows);
});

app.get('/api/properties/:id', authenticate, (req, res) => {
  const p = db.prepare(`
    SELECT p.*, u.name as listing_broker_name
    FROM properties p LEFT JOIN users u ON p.listing_broker_id = u.id
    WHERE p.id = ?
  `).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Property not found' });

  const inquiries = db.prepare(`
    SELECT i.*, c.first_name, c.last_name, c.email, c.phone, c.tags, co.name as company_name
    FROM inquiries i
    LEFT JOIN contacts c ON i.contact_id = c.id
    LEFT JOIN companies co ON c.company_id = co.id
    WHERE i.property_id = ? ORDER BY i.created_at DESC
  `).all(req.params.id);

  const deals = db.prepare(`
    SELECT d.*, c.first_name, c.last_name, u.name as assigned_to_name
    FROM deals d
    LEFT JOIN contacts c ON d.contact_id = c.id
    LEFT JOIN users u ON d.assigned_to = u.id
    WHERE d.property_id = ? ORDER BY d.created_at DESC
  `).all(req.params.id);

  const tasks = db.prepare('SELECT * FROM tasks WHERE property_id = ? ORDER BY due_date').all(req.params.id);

  res.json({ ...p, inquiries, deals, tasks });
});

app.post('/api/properties', authenticate, (req, res) => {
  const f = req.body;
  const result = db.prepare(`
    INSERT INTO properties (name, address, city, state, submarket, type, size_sf, asking_rate, rate_type, status,
    is_listing, list_date, expiration_date, listing_broker_id, commission_rate, marketing_notes, clear_height, dock_doors, notes, created_by)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(f.name, f.address, f.city, f.state || 'WA', f.submarket, f.type || 'industrial', f.size_sf, f.asking_rate,
    f.rate_type || 'NNN', f.status || 'available', f.is_listing ? 1 : 0, f.list_date, f.expiration_date,
    f.listing_broker_id || null, f.commission_rate, f.marketing_notes, f.clear_height, f.dock_doors, f.notes, req.user.id);
  const row = db.prepare('SELECT * FROM properties WHERE id = ?').get(result.lastInsertRowid);
  logActivity('create', 'property', row.id, f.address, f.is_listing ? 'New listing added' : null, req.user.id);
  res.json(row);
});

app.put('/api/properties/:id', authenticate, (req, res) => {
  const f = req.body;
  db.prepare(`
    UPDATE properties SET name=?, address=?, city=?, state=?, submarket=?, type=?, size_sf=?, asking_rate=?, rate_type=?, status=?,
    is_listing=?, list_date=?, expiration_date=?, listing_broker_id=?, commission_rate=?, marketing_notes=?, clear_height=?, dock_doors=?, notes=?, updated_at=?
    WHERE id=?
  `).run(f.name, f.address, f.city, f.state, f.submarket, f.type, f.size_sf, f.asking_rate, f.rate_type, f.status,
    f.is_listing ? 1 : 0, f.list_date, f.expiration_date, f.listing_broker_id || null, f.commission_rate,
    f.marketing_notes, f.clear_height, f.dock_doors, f.notes, now(), req.params.id);
  const row = db.prepare('SELECT * FROM properties WHERE id = ?').get(req.params.id);
  logActivity('update', 'property', row.id, row.address, null, req.user.id);
  res.json(row);
});

app.delete('/api/properties/:id', authenticate, (req, res) => {
  const p = db.prepare('SELECT address FROM properties WHERE id = ?').get(req.params.id);
  db.prepare('DELETE FROM inquiries WHERE property_id = ?').run(req.params.id);
  db.prepare('DELETE FROM properties WHERE id = ?').run(req.params.id);
  logActivity('delete', 'property', parseInt(req.params.id), p?.address, null, req.user.id);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DEALS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/deals', authenticate, (req, res) => {
  const rows = db.prepare(`
    SELECT d.*, c.first_name, c.last_name, co.name as company_name,
    p.address as property_address, p.name as property_name,
    u.name as assigned_to_name, u2.name as created_by_name
    FROM deals d
    LEFT JOIN contacts c ON d.contact_id = c.id
    LEFT JOIN companies co ON c.company_id = co.id
    LEFT JOIN properties p ON d.property_id = p.id
    LEFT JOIN users u ON d.assigned_to = u.id
    LEFT JOIN users u2 ON d.created_by = u2.id
    ORDER BY d.updated_at DESC
  `).all();
  res.json(rows);
});

app.post('/api/deals', authenticate, (req, res) => {
  const f = req.body;
  if (!f.title) return res.status(400).json({ error: 'Deal title required' });
  const result = db.prepare(`
    INSERT INTO deals (title, stage, deal_type, contact_id, property_id, value, size_sf, close_date, notes, assigned_to, created_by)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
  `).run(f.title, f.stage || 'prospect', f.deal_type || 'lease_tenant', f.contact_id || null, f.property_id || null,
    f.value, f.size_sf, f.close_date, f.notes, f.assigned_to || req.user.id, req.user.id);
  const row = db.prepare('SELECT * FROM deals WHERE id = ?').get(result.lastInsertRowid);
  logActivity('create', 'deal', row.id, f.title, `Stage: ${row.stage}`, req.user.id);
  res.json(row);
});

app.put('/api/deals/:id', authenticate, (req, res) => {
  const old = db.prepare('SELECT * FROM deals WHERE id = ?').get(req.params.id);
  const f = req.body;
  db.prepare(`
    UPDATE deals SET title=?, stage=?, deal_type=?, contact_id=?, property_id=?, value=?, size_sf=?, close_date=?, notes=?, assigned_to=?, updated_at=?
    WHERE id=?
  `).run(f.title, f.stage, f.deal_type, f.contact_id || null, f.property_id || null, f.value, f.size_sf,
    f.close_date, f.notes, f.assigned_to, now(), req.params.id);
  const row = db.prepare('SELECT * FROM deals WHERE id = ?').get(req.params.id);

  if (old && old.stage !== f.stage) {
    logActivity('stage_change', 'deal', row.id, row.title, `${old.stage} → ${f.stage}`, req.user.id);
  } else {
    logActivity('update', 'deal', row.id, row.title, null, req.user.id);
  }
  res.json(row);
});

app.delete('/api/deals/:id', authenticate, (req, res) => {
  const d = db.prepare('SELECT title FROM deals WHERE id = ?').get(req.params.id);
  db.prepare('DELETE FROM deals WHERE id = ?').run(req.params.id);
  logActivity('delete', 'deal', parseInt(req.params.id), d?.title, null, req.user.id);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// TASKS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/tasks', authenticate, (req, res) => {
  const rows = db.prepare(`
    SELECT t.*, u.name as assigned_to_name, u2.name as created_by_name,
    c.first_name as contact_first, c.last_name as contact_last,
    d.title as deal_title, p.address as property_address
    FROM tasks t
    LEFT JOIN users u ON t.assigned_to = u.id
    LEFT JOIN users u2 ON t.created_by = u2.id
    LEFT JOIN contacts c ON t.contact_id = c.id
    LEFT JOIN deals d ON t.deal_id = d.id
    LEFT JOIN properties p ON t.property_id = p.id
    ORDER BY t.completed ASC, t.due_date ASC
  `).all();
  res.json(rows);
});

app.post('/api/tasks', authenticate, (req, res) => {
  const f = req.body;
  if (!f.title) return res.status(400).json({ error: 'Task title required' });
  const result = db.prepare(`
    INSERT INTO tasks (title, due_date, priority, contact_id, deal_id, property_id, assigned_to, notes, created_by)
    VALUES (?,?,?,?,?,?,?,?,?)
  `).run(f.title, f.due_date, f.priority || 'medium', f.contact_id || null, f.deal_id || null,
    f.property_id || null, f.assigned_to || req.user.id, f.notes, req.user.id);
  const row = db.prepare('SELECT * FROM tasks WHERE id = ?').get(result.lastInsertRowid);
  logActivity('create', 'task', row.id, f.title, null, req.user.id);
  res.json(row);
});

app.put('/api/tasks/:id', authenticate, (req, res) => {
  const f = req.body;
  const old = db.prepare('SELECT * FROM tasks WHERE id = ?').get(req.params.id);
  db.prepare(`
    UPDATE tasks SET title=?, due_date=?, completed=?, priority=?, contact_id=?, deal_id=?, property_id=?, assigned_to=?, notes=?
    WHERE id=?
  `).run(f.title, f.due_date, f.completed ? 1 : 0, f.priority, f.contact_id || null, f.deal_id || null,
    f.property_id || null, f.assigned_to, f.notes, req.params.id);
  const row = db.prepare('SELECT * FROM tasks WHERE id = ?').get(req.params.id);

  if (!old?.completed && f.completed) {
    logActivity('complete', 'task', row.id, row.title, null, req.user.id);
  } else {
    logActivity('update', 'task', row.id, row.title, null, req.user.id);
  }
  res.json(row);
});

app.delete('/api/tasks/:id', authenticate, (req, res) => {
  const t = db.prepare('SELECT title FROM tasks WHERE id = ?').get(req.params.id);
  db.prepare('DELETE FROM tasks WHERE id = ?').run(req.params.id);
  logActivity('delete', 'task', parseInt(req.params.id), t?.title, null, req.user.id);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// INQUIRIES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/properties/:propertyId/inquiries', authenticate, (req, res) => {
  const rows = db.prepare(`
    SELECT i.*, c.first_name, c.last_name, c.email, c.phone, c.tags, co.name as company_name
    FROM inquiries i
    LEFT JOIN contacts c ON i.contact_id = c.id
    LEFT JOIN companies co ON c.company_id = co.id
    WHERE i.property_id = ? ORDER BY i.created_at DESC
  `).all(req.params.propertyId);
  res.json(rows);
});

app.post('/api/inquiries', authenticate, (req, res) => {
  const { property_id, contact_id, status, interest_level, size_need, notes } = req.body;
  if (!property_id || !contact_id) return res.status(400).json({ error: 'Property and contact required' });
  const result = db.prepare(
    'INSERT INTO inquiries (property_id, contact_id, status, interest_level, size_need, notes, created_by) VALUES (?,?,?,?,?,?,?)'
  ).run(property_id, contact_id, status || 'new', interest_level || 'medium', size_need, notes, req.user.id);
  const row = db.prepare('SELECT * FROM inquiries WHERE id = ?').get(result.lastInsertRowid);
  const contact = db.prepare('SELECT first_name, last_name FROM contacts WHERE id = ?').get(contact_id);
  const prop = db.prepare('SELECT address FROM properties WHERE id = ?').get(property_id);
  logActivity('create', 'inquiry', row.id,
    `${contact?.first_name} ${contact?.last_name || ''} → ${prop?.address}`.trim(),
    null, req.user.id);
  res.json(row);
});

app.put('/api/inquiries/:id', authenticate, (req, res) => {
  const { status, interest_level, size_need, notes } = req.body;
  db.prepare('UPDATE inquiries SET status=?, interest_level=?, size_need=?, notes=?, updated_at=? WHERE id=?')
    .run(status, interest_level, size_need, notes, now(), req.params.id);
  const row = db.prepare('SELECT * FROM inquiries WHERE id = ?').get(req.params.id);
  logActivity('update', 'inquiry', row.id, null, `Status: ${status}`, req.user.id);
  res.json(row);
});

app.delete('/api/inquiries/:id', authenticate, (req, res) => {
  db.prepare('DELETE FROM inquiries WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD / STATS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/stats', authenticate, (req, res) => {
  const totalContacts = db.prepare('SELECT COUNT(*) as c FROM contacts').get().c;
  const totalProperties = db.prepare('SELECT COUNT(*) as c FROM properties').get().c;
  const activeListings = db.prepare("SELECT COUNT(*) as c FROM properties WHERE is_listing = 1 AND status IN ('available','under_offer')").get().c;
  const activeDeals = db.prepare("SELECT COUNT(*) as c FROM deals WHERE stage NOT IN ('closed_won','closed_lost')").get().c;
  const closedWon = db.prepare("SELECT COUNT(*) as c FROM deals WHERE stage = 'closed_won'").get().c;

  const tasksDueToday = db.prepare("SELECT COUNT(*) as c FROM tasks WHERE completed = 0 AND due_date = date('now')").get().c;
  const tasksOverdue = db.prepare("SELECT COUNT(*) as c FROM tasks WHERE completed = 0 AND due_date < date('now') AND due_date IS NOT NULL").get().c;
  const tasksUpcoming = db.prepare("SELECT COUNT(*) as c FROM tasks WHERE completed = 0 AND due_date > date('now') AND due_date <= date('now', '+7 days')").get().c;

  const dealsByStage = db.prepare("SELECT stage, COUNT(*) as count, COALESCE(SUM(CAST(REPLACE(REPLACE(value,'$',''),',','') AS REAL)),0) as total_value FROM deals WHERE stage NOT IN ('closed_won','closed_lost') GROUP BY stage").all();

  const recentActivity = db.prepare(`
    SELECT a.*, u.name as user_name
    FROM activity_log a LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.created_at DESC LIMIT 20
  `).all();

  const upcomingTasks = db.prepare(`
    SELECT t.*, u.name as assigned_to_name
    FROM tasks t LEFT JOIN users u ON t.assigned_to = u.id
    WHERE t.completed = 0
    ORDER BY CASE WHEN t.due_date IS NULL THEN 1 ELSE 0 END, t.due_date ASC
    LIMIT 10
  `).all();

  res.json({
    totalContacts, totalProperties, activeListings, activeDeals, closedWon,
    tasksDueToday, tasksOverdue, tasksUpcoming,
    dealsByStage, recentActivity, upcomingTasks
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ACTIVITY LOG
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/activity', authenticate, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const rows = db.prepare(`
    SELECT a.*, u.name as user_name
    FROM activity_log a LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.created_at DESC LIMIT ?
  `).all(limit);
  res.json(rows);
});

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL SEARCH
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/search', authenticate, (req, res) => {
  const q = req.query.q;
  if (!q || q.length < 2) return res.json({ contacts: [], companies: [], properties: [], deals: [] });
  const like = `%${q}%`;

  const contacts = db.prepare(`
    SELECT id, first_name, last_name, email, phone, tags, 'contact' as _type
    FROM contacts WHERE first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR phone LIKE ? OR tags LIKE ? LIMIT 10
  `).all(like, like, like, like, like);

  const companies = db.prepare(`
    SELECT id, name, type, 'company' as _type
    FROM companies WHERE name LIKE ? OR industry LIKE ? LIMIT 10
  `).all(like, like);

  const properties = db.prepare(`
    SELECT id, name, address, city, type, status, 'property' as _type
    FROM properties WHERE address LIKE ? OR name LIKE ? OR city LIKE ? OR submarket LIKE ? LIMIT 10
  `).all(like, like, like, like);

  const deals = db.prepare(`
    SELECT id, title, stage, deal_type, 'deal' as _type
    FROM deals WHERE title LIKE ? LIMIT 10
  `).all(like);

  res.json({ contacts, companies, properties, deals });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CSV EXPORT
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/export/:entity', authenticate, (req, res) => {
  const entity = req.params.entity;
  let rows, filename;

  if (entity === 'contacts') {
    rows = db.prepare(`
      SELECT c.first_name, c.last_name, co.name as company, c.email, c.phone, c.tags, c.submarket, c.size_requirement, c.industry, c.notes, c.created_at
      FROM contacts c LEFT JOIN companies co ON c.company_id = co.id ORDER BY c.first_name
    `).all();
    filename = 'contacts_export.csv';
  } else if (entity === 'deals') {
    rows = db.prepare(`
      SELECT d.title, d.stage, d.deal_type, c.first_name || ' ' || COALESCE(c.last_name,'') as contact,
      p.address as property, d.value, d.close_date, u.name as assigned_to, d.notes, d.created_at
      FROM deals d LEFT JOIN contacts c ON d.contact_id = c.id LEFT JOIN properties p ON d.property_id = p.id
      LEFT JOIN users u ON d.assigned_to = u.id ORDER BY d.updated_at DESC
    `).all();
    filename = 'deals_export.csv';
  } else if (entity === 'properties') {
    rows = db.prepare(`
      SELECT p.name, p.address, p.city, p.state, p.submarket, p.type, p.size_sf, p.asking_rate, p.rate_type,
      p.status, p.is_listing, p.list_date, p.expiration_date, p.notes, p.created_at
      FROM properties p ORDER BY p.address
    `).all();
    filename = 'properties_export.csv';
  } else {
    return res.status(400).json({ error: 'Invalid entity. Use: contacts, deals, properties' });
  }

  if (!rows.length) return res.status(404).json({ error: 'No data to export' });

  const headers = Object.keys(rows[0]);
  const csv = [
    headers.join(','),
    ...rows.map(r => headers.map(h => {
      const val = r[h] == null ? '' : String(r[h]);
      return val.includes(',') || val.includes('"') || val.includes('\n') ? `"${val.replace(/"/g, '""')}"` : val;
    }).join(','))
  ].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csv);
});

// ═══════════════════════════════════════════════════════════════════════════════
// AI CHAT PROXY
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/ai/chat', authenticate, (req, res) => {
  const user = db.prepare('SELECT claude_api_key FROM users WHERE id = ?').get(req.user.id);
  if (!user?.claude_api_key) return res.status(400).json({ error: 'No Claude API key configured. Add yours in Settings.' });

  // Gather CRM context for the AI
  const contactCount = db.prepare('SELECT COUNT(*) as c FROM contacts').get().c;
  const dealCount = db.prepare("SELECT COUNT(*) as c FROM deals WHERE stage NOT IN ('closed_won','closed_lost')").get().c;
  const listingCount = db.prepare("SELECT COUNT(*) as c FROM properties WHERE is_listing = 1").get().c;

  const { messages, context } = req.body;
  if (!messages || !messages.length) return res.status(400).json({ error: 'No messages provided' });

  let systemPrompt = `You are an AI assistant embedded in KM Team CRM, a commercial real estate CRM for brokers at Kidder Mathews specializing in the Seattle Eastside market (Bellevue, Kirkland, Redmond, Bothell, Woodinville, Issaquah, Snoqualmie, and north to Everett).

Current CRM stats: ${contactCount} contacts, ${dealCount} active deals, ${listingCount} active listings.

Help with: drafting professional emails, writing LOIs and proposals, analyzing deals and comps, creating call lists, summarizing deal status, market research, and general CRE brokerage tasks. Be concise, professional, and practical. Match a polished brokerage tone.`;

  if (context) {
    systemPrompt += `\n\nAdditional context from CRM:\n${context}`;
  }

  const payload = JSON.stringify({
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 4096,
    system: systemPrompt,
    messages
  });

  const options = {
    hostname: 'api.anthropic.com',
    path: '/v1/messages',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': user.claude_api_key,
      'anthropic-version': '2023-06-01',
      'Content-Length': Buffer.byteLength(payload)
    }
  };

  const apiReq = https.request(options, (apiRes) => {
    let data = '';
    apiRes.on('data', chunk => data += chunk);
    apiRes.on('end', () => {
      try {
        const parsed = JSON.parse(data);
        if (parsed.error) return res.status(400).json({ error: parsed.error.message || 'API error' });
        res.json({ content: parsed.content?.[0]?.text || '' });
      } catch {
        res.status(500).json({ error: 'Failed to parse AI response' });
      }
    });
  });

  apiReq.on('error', (e) => res.status(500).json({ error: e.message }));
  apiReq.write(payload);
  apiReq.end();
});

// ═══════════════════════════════════════════════════════════════════════════════
// SPA FALLBACK
// ═══════════════════════════════════════════════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  🏢 KM Team CRM running at http://localhost:${PORT}\n`);
});
