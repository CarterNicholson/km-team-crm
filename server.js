const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const https = require('https');
const fs = require('fs');

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

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════════════════════════════════════
// DATABASE SETUP
// ═══════════════════════════════════════════════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost/km_crm',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database schema on startup
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'broker',
        claude_api_key TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS companies (
        id SERIAL PRIMARY KEY,
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
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS contacts (
        id SERIAL PRIMARY KEY,
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
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS properties (
        id SERIAL PRIMARY KEY,
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
        is_listing BOOLEAN DEFAULT FALSE,
        list_date TEXT,
        expiration_date TEXT,
        listing_broker_id INTEGER REFERENCES users(id),
        commission_rate TEXT,
        marketing_notes TEXT,
        clear_height TEXT,
        dock_doors INTEGER,
        notes TEXT,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS deals (
        id SERIAL PRIMARY KEY,
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
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        due_date TEXT,
        completed BOOLEAN DEFAULT FALSE,
        priority TEXT DEFAULT 'medium',
        contact_id INTEGER,
        deal_id INTEGER,
        property_id INTEGER,
        assigned_to INTEGER REFERENCES users(id),
        notes TEXT,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS inquiries (
        id SERIAL PRIMARY KEY,
        property_id INTEGER NOT NULL REFERENCES properties(id),
        contact_id INTEGER NOT NULL REFERENCES contacts(id),
        status TEXT DEFAULT 'new',
        interest_level TEXT DEFAULT 'medium',
        size_need TEXT,
        notes TEXT,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS activity_log (
        id SERIAL PRIMARY KEY,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id INTEGER,
        entity_name TEXT,
        details TEXT,
        user_id INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log('Database schema initialized successfully');
  } catch (err) {
    console.error('Error initializing database:', err);
    process.exit(1);
  }
}

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

async function logActivity(action, entityType, entityId, entityName, details, userId) {
  try {
    await pool.query(
      'INSERT INTO activity_log (action, entity_type, entity_id, entity_name, details, user_id) VALUES ($1, $2, $3, $4, $5, $6)',
      [action, entityType, entityId, entityName, details || null, userId]
    );
  } catch (err) {
    console.error('Error logging activity:', err);
  }
}

function now() {
  return new Date().toISOString();
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/auth/status', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) as c FROM users');
    res.json({ hasUsers: parseInt(result.rows[0].c) > 0 });
  } catch (err) {
    console.error('Error checking auth status:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/auth/setup', async (req, res) => {
  try {
    const existing = await pool.query('SELECT COUNT(*) as c FROM users');
    if (parseInt(existing.rows[0].c) > 0) return res.status(400).json({ error: 'Setup already completed' });
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const hash = hashPassword(password);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
      [name, email, hash, 'admin']
    );
    const user = { id: result.rows[0].id, name, email, role: 'admin' };
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    await logActivity('create', 'user', user.id, name, 'Initial admin setup', user.id);
    res.json({ token, user });
  } catch (err) {
    console.error('Error during setup:', err);
    res.status(500).json({ error: 'Setup failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    await logActivity('login', 'user', user.id, user.name, null, user.id);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, role, claude_api_key FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ ...user, hasApiKey: !!user.claude_api_key });
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// USER ROUTES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/users', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, role, created_at FROM users ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/users', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password required' });
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }
    const hash = hashPassword(password);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
      [name, email, hash, role || 'broker']
    );
    const user = result.rows[0];
    await logActivity('create', 'user', user.id, name, `New team member added (${role || 'broker'})`, req.user.id);
    res.json(user);
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (req.user.id !== id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const { name, email, claude_api_key } = req.body;
    await pool.query(
      'UPDATE users SET name = COALESCE($1, name), email = COALESCE($2, email), claude_api_key = $3 WHERE id = $4',
      [name || null, email || null, claude_api_key !== undefined ? claude_api_key : null, id]
    );
    const result = await pool.query('SELECT id, name, email, role, claude_api_key FROM users WHERE id = $1', [id]);
    const user = result.rows[0];
    res.json({ ...user, hasApiKey: !!user.claude_api_key });
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.put('/api/users/:id/password', authenticate, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (req.user.id !== id) return res.status(403).json({ error: 'Forbidden' });
    const { current_password, new_password } = req.body;
    if (!new_password || new_password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    const user = result.rows[0];
    if (!verifyPassword(current_password, user.password_hash)) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashPassword(new_password), id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error updating password:', err);
    res.status(500).json({ error: 'Failed to update password' });
  }
});

app.delete('/api/users/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    if (req.user.id === parseInt(req.params.id)) return res.status(400).json({ error: 'Cannot delete yourself' });
    const result = await pool.query('SELECT name FROM users WHERE id = $1', [req.params.id]);
    const u = result.rows[0];
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    await logActivity('delete', 'user', parseInt(req.params.id), u?.name, 'Team member removed', req.user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// COMPANIES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/companies', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, u.name as created_by_name,
      (SELECT COUNT(*) FROM contacts WHERE company_id = c.id) as contact_count
      FROM companies c LEFT JOIN users u ON c.created_by = u.id
      ORDER BY c.name
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching companies:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/companies', authenticate, async (req, res) => {
  try {
    const { name, type, industry, website, phone, address, city, state, submarket, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'Company name required' });
    const result = await pool.query(
      'INSERT INTO companies (name, type, industry, website, phone, address, city, state, submarket, notes, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
      [name, type, industry, website, phone, address, city, state || 'WA', submarket, notes, req.user.id]
    );
    const row = result.rows[0];
    await logActivity('create', 'company', row.id, name, null, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error creating company:', err);
    res.status(500).json({ error: 'Failed to create company' });
  }
});

app.put('/api/companies/:id', authenticate, async (req, res) => {
  try {
    const { name, type, industry, website, phone, address, city, state, submarket, notes } = req.body;
    await pool.query(
      'UPDATE companies SET name=$1, type=$2, industry=$3, website=$4, phone=$5, address=$6, city=$7, state=$8, submarket=$9, notes=$10, updated_at=$11 WHERE id=$12',
      [name, type, industry, website, phone, address, city, state, submarket, notes, now(), req.params.id]
    );
    const result = await pool.query('SELECT * FROM companies WHERE id = $1', [req.params.id]);
    const row = result.rows[0];
    await logActivity('update', 'company', row.id, row.name, null, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error updating company:', err);
    res.status(500).json({ error: 'Failed to update company' });
  }
});

app.delete('/api/companies/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT name FROM companies WHERE id = $1', [req.params.id]);
    const c = result.rows[0];
    await pool.query('UPDATE contacts SET company_id = NULL WHERE company_id = $1', [req.params.id]);
    await pool.query('DELETE FROM companies WHERE id = $1', [req.params.id]);
    await logActivity('delete', 'company', parseInt(req.params.id), c?.name, null, req.user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting company:', err);
    res.status(500).json({ error: 'Failed to delete company' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CONTACTS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/contacts', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, co.name as company_name, u.name as created_by_name
      FROM contacts c
      LEFT JOIN companies co ON c.company_id = co.id
      LEFT JOIN users u ON c.created_by = u.id
      ORDER BY c.first_name, c.last_name
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching contacts:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/contacts/:id', authenticate, async (req, res) => {
  try {
    const contactResult = await pool.query(`
      SELECT c.*, co.name as company_name FROM contacts c
      LEFT JOIN companies co ON c.company_id = co.id WHERE c.id = $1
    `, [req.params.id]);
    const c = contactResult.rows[0];
    if (!c) return res.status(404).json({ error: 'Contact not found' });

    const dealsResult = await pool.query('SELECT * FROM deals WHERE contact_id = $1 ORDER BY created_at DESC', [req.params.id]);
    const tasksResult = await pool.query('SELECT * FROM tasks WHERE contact_id = $1 ORDER BY due_date', [req.params.id]);
    const inquiriesResult = await pool.query(`
      SELECT i.*, p.address as property_address, p.name as property_name
      FROM inquiries i LEFT JOIN properties p ON i.property_id = p.id
      WHERE i.contact_id = $1 ORDER BY i.created_at DESC
    `, [req.params.id]);

    res.json({ ...c, deals: dealsResult.rows, tasks: tasksResult.rows, inquiries: inquiriesResult.rows });
  } catch (err) {
    console.error('Error fetching contact:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/contacts', authenticate, async (req, res) => {
  try {
    const { first_name, last_name, company_id, email, phone, tags, submarket, size_requirement, industry, notes } = req.body;
    if (!first_name) return res.status(400).json({ error: 'First name required' });
    const result = await pool.query(
      'INSERT INTO contacts (first_name, last_name, company_id, email, phone, tags, submarket, size_requirement, industry, notes, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
      [first_name, last_name, company_id || null, email, phone, tags || '', submarket, size_requirement, industry, notes, req.user.id]
    );
    const row = result.rows[0];
    await logActivity('create', 'contact', row.id, `${first_name} ${last_name || ''}`.trim(), null, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error creating contact:', err);
    res.status(500).json({ error: 'Failed to create contact' });
  }
});

app.put('/api/contacts/:id', authenticate, async (req, res) => {
  try {
    const { first_name, last_name, company_id, email, phone, tags, submarket, size_requirement, industry, notes } = req.body;
    await pool.query(
      'UPDATE contacts SET first_name=$1, last_name=$2, company_id=$3, email=$4, phone=$5, tags=$6, submarket=$7, size_requirement=$8, industry=$9, notes=$10, updated_at=$11 WHERE id=$12',
      [first_name, last_name, company_id || null, email, phone, tags || '', submarket, size_requirement, industry, notes, now(), req.params.id]
    );
    const result = await pool.query('SELECT * FROM contacts WHERE id = $1', [req.params.id]);
    const row = result.rows[0];
    await logActivity('update', 'contact', row.id, `${row.first_name} ${row.last_name || ''}`.trim(), null, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error updating contact:', err);
    res.status(500).json({ error: 'Failed to update contact' });
  }
});

app.delete('/api/contacts/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT first_name, last_name FROM contacts WHERE id = $1', [req.params.id]);
    const c = result.rows[0];
    await pool.query('DELETE FROM contacts WHERE id = $1', [req.params.id]);
    await logActivity('delete', 'contact', parseInt(req.params.id), `${c?.first_name} ${c?.last_name || ''}`.trim(), null, req.user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting contact:', err);
    res.status(500).json({ error: 'Failed to delete contact' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/properties', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, u.name as listing_broker_name, u2.name as created_by_name,
      (SELECT COUNT(*) FROM inquiries WHERE property_id = p.id) as inquiry_count,
      (SELECT COUNT(*) FROM deals WHERE property_id = p.id) as deal_count
      FROM properties p
      LEFT JOIN users u ON p.listing_broker_id = u.id
      LEFT JOIN users u2 ON p.created_by = u2.id
      ORDER BY p.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching properties:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/properties/listings', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, u.name as listing_broker_name,
      (SELECT COUNT(*) FROM inquiries WHERE property_id = p.id) as inquiry_count,
      (SELECT COUNT(*) FROM deals WHERE property_id = p.id) as deal_count
      FROM properties p
      LEFT JOIN users u ON p.listing_broker_id = u.id
      WHERE p.is_listing = true
      ORDER BY p.list_date DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching listings:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/properties/:id', authenticate, async (req, res) => {
  try {
    const propResult = await pool.query(`
      SELECT p.*, u.name as listing_broker_name
      FROM properties p LEFT JOIN users u ON p.listing_broker_id = u.id
      WHERE p.id = $1
    `, [req.params.id]);
    const p = propResult.rows[0];
    if (!p) return res.status(404).json({ error: 'Property not found' });

    const inquiriesResult = await pool.query(`
      SELECT i.*, c.first_name, c.last_name, c.email, c.phone, c.tags, co.name as company_name
      FROM inquiries i
      LEFT JOIN contacts c ON i.contact_id = c.id
      LEFT JOIN companies co ON c.company_id = co.id
      WHERE i.property_id = $1 ORDER BY i.created_at DESC
    `, [req.params.id]);

    const dealsResult = await pool.query(`
      SELECT d.*, c.first_name, c.last_name, u.name as assigned_to_name
      FROM deals d
      LEFT JOIN contacts c ON d.contact_id = c.id
      LEFT JOIN users u ON d.assigned_to = u.id
      WHERE d.property_id = $1 ORDER BY d.created_at DESC
    `, [req.params.id]);

    const tasksResult = await pool.query('SELECT * FROM tasks WHERE property_id = $1 ORDER BY due_date', [req.params.id]);

    res.json({ ...p, inquiries: inquiriesResult.rows, deals: dealsResult.rows, tasks: tasksResult.rows });
  } catch (err) {
    console.error('Error fetching property:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/properties', authenticate, async (req, res) => {
  try {
    const f = req.body;
    const result = await pool.query(`
      INSERT INTO properties (name, address, city, state, submarket, type, size_sf, asking_rate, rate_type, status,
      is_listing, list_date, expiration_date, listing_broker_id, commission_rate, marketing_notes, clear_height, dock_doors, notes, created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) RETURNING *
    `, [f.name, f.address, f.city, f.state || 'WA', f.submarket, f.type || 'industrial', f.size_sf, f.asking_rate,
      f.rate_type || 'NNN', f.status || 'available', f.is_listing ? true : false, f.list_date, f.expiration_date,
      f.listing_broker_id || null, f.commission_rate, f.marketing_notes, f.clear_height, f.dock_doors, f.notes, req.user.id]);
    const row = result.rows[0];
    await logActivity('create', 'property', row.id, f.address, f.is_listing ? 'New listing added' : null, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error creating property:', err);
    res.status(500).json({ error: 'Failed to create property' });
  }
});

app.put('/api/properties/:id', authenticate, async (req, res) => {
  try {
    const f = req.body;
    await pool.query(`
      UPDATE properties SET name=$1, address=$2, city=$3, state=$4, submarket=$5, type=$6, size_sf=$7, asking_rate=$8, rate_type=$9, status=$10,
      is_listing=$11, list_date=$12, expiration_date=$13, listing_broker_id=$14, commission_rate=$15, marketing_notes=$16, clear_height=$17, dock_doors=$18, notes=$19, updated_at=$20
      WHERE id=$21
    `, [f.name, f.address, f.city, f.state, f.submarket, f.type, f.size_sf, f.asking_rate, f.rate_type, f.status,
      f.is_listing ? true : false, f.list_date, f.expiration_date, f.listing_broker_id || null, f.commission_rate,
      f.marketing_notes, f.clear_height, f.dock_doors, f.notes, now(), req.params.id]);
    const result = await pool.query('SELECT * FROM properties WHERE id = $1', [req.params.id]);
    const row = result.rows[0];
    await logActivity('update', 'property', row.id, row.address, null, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error updating property:', err);
    res.status(500).json({ error: 'Failed to update property' });
  }
});

app.delete('/api/properties/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT address FROM properties WHERE id = $1', [req.params.id]);
    const p = result.rows[0];
    await pool.query('DELETE FROM inquiries WHERE property_id = $1', [req.params.id]);
    await pool.query('DELETE FROM properties WHERE id = $1', [req.params.id]);
    await logActivity('delete', 'property', parseInt(req.params.id), p?.address, null, req.user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting property:', err);
    res.status(500).json({ error: 'Failed to delete property' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DEALS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/deals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
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
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching deals:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/deals', authenticate, async (req, res) => {
  try {
    const f = req.body;
    if (!f.title) return res.status(400).json({ error: 'Deal title required' });
    const result = await pool.query(`
      INSERT INTO deals (title, stage, deal_type, contact_id, property_id, value, size_sf, close_date, notes, assigned_to, created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *
    `, [f.title, f.stage || 'prospect', f.deal_type || 'lease_tenant', f.contact_id || null, f.property_id || null,
      f.value, f.size_sf, f.close_date, f.notes, f.assigned_to || req.user.id, req.user.id]);
    const row = result.rows[0];
    await logActivity('create', 'deal', row.id, f.title, `Stage: ${row.stage}`, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error creating deal:', err);
    res.status(500).json({ error: 'Failed to create deal' });
  }
});

app.put('/api/deals/:id', authenticate, async (req, res) => {
  try {
    const oldResult = await pool.query('SELECT * FROM deals WHERE id = $1', [req.params.id]);
    const old = oldResult.rows[0];
    const f = req.body;
    await pool.query(`
      UPDATE deals SET title=$1, stage=$2, deal_type=$3, contact_id=$4, property_id=$5, value=$6, size_sf=$7, close_date=$8, notes=$9, assigned_to=$10, updated_at=$11
      WHERE id=$12
    `, [f.title, f.stage, f.deal_type, f.contact_id || null, f.property_id || null, f.value, f.size_sf,
      f.close_date, f.notes, f.assigned_to, now(), req.params.id]);
    const result = await pool.query('SELECT * FROM deals WHERE id = $1', [req.params.id]);
    const row = result.rows[0];

    if (old && old.stage !== f.stage) {
      await logActivity('stage_change', 'deal', row.id, row.title, `${old.stage} → ${f.stage}`, req.user.id);
    } else {
      await logActivity('update', 'deal', row.id, row.title, null, req.user.id);
    }
    res.json(row);
  } catch (err) {
    console.error('Error updating deal:', err);
    res.status(500).json({ error: 'Failed to update deal' });
  }
});

app.delete('/api/deals/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT title FROM deals WHERE id = $1', [req.params.id]);
    const d = result.rows[0];
    await pool.query('DELETE FROM deals WHERE id = $1', [req.params.id]);
    await logActivity('delete', 'deal', parseInt(req.params.id), d?.title, null, req.user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting deal:', err);
    res.status(500).json({ error: 'Failed to delete deal' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// TASKS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/tasks', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
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
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching tasks:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/tasks', authenticate, async (req, res) => {
  try {
    const f = req.body;
    if (!f.title) return res.status(400).json({ error: 'Task title required' });
    const result = await pool.query(`
      INSERT INTO tasks (title, due_date, priority, contact_id, deal_id, property_id, assigned_to, notes, created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
    `, [f.title, f.due_date, f.priority || 'medium', f.contact_id || null, f.deal_id || null,
      f.property_id || null, f.assigned_to || req.user.id, f.notes, req.user.id]);
    const row = result.rows[0];
    await logActivity('create', 'task', row.id, f.title, null, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error creating task:', err);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

app.put('/api/tasks/:id', authenticate, async (req, res) => {
  try {
    const f = req.body;
    const oldResult = await pool.query('SELECT * FROM tasks WHERE id = $1', [req.params.id]);
    const old = oldResult.rows[0];
    await pool.query(`
      UPDATE tasks SET title=$1, due_date=$2, completed=$3, priority=$4, contact_id=$5, deal_id=$6, property_id=$7, assigned_to=$8, notes=$9
      WHERE id=$10
    `, [f.title, f.due_date, f.completed ? true : false, f.priority, f.contact_id || null, f.deal_id || null,
      f.property_id || null, f.assigned_to, f.notes, req.params.id]);
    const result = await pool.query('SELECT * FROM tasks WHERE id = $1', [req.params.id]);
    const row = result.rows[0];

    if (!old?.completed && f.completed) {
      await logActivity('complete', 'task', row.id, row.title, null, req.user.id);
    } else {
      await logActivity('update', 'task', row.id, row.title, null, req.user.id);
    }
    res.json(row);
  } catch (err) {
    console.error('Error updating task:', err);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

app.delete('/api/tasks/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT title FROM tasks WHERE id = $1', [req.params.id]);
    const t = result.rows[0];
    await pool.query('DELETE FROM tasks WHERE id = $1', [req.params.id]);
    await logActivity('delete', 'task', parseInt(req.params.id), t?.title, null, req.user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting task:', err);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// INQUIRIES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/properties/:propertyId/inquiries', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT i.*, c.first_name, c.last_name, c.email, c.phone, c.tags, co.name as company_name
      FROM inquiries i
      LEFT JOIN contacts c ON i.contact_id = c.id
      LEFT JOIN companies co ON c.company_id = co.id
      WHERE i.property_id = $1 ORDER BY i.created_at DESC
    `, [req.params.propertyId]);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching inquiries:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/inquiries', authenticate, async (req, res) => {
  try {
    const { property_id, contact_id, status, interest_level, size_need, notes } = req.body;
    if (!property_id || !contact_id) return res.status(400).json({ error: 'Property and contact required' });
    const result = await pool.query(
      'INSERT INTO inquiries (property_id, contact_id, status, interest_level, size_need, notes, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [property_id, contact_id, status || 'new', interest_level || 'medium', size_need, notes, req.user.id]
    );
    const row = result.rows[0];
    const contactResult = await pool.query('SELECT first_name, last_name FROM contacts WHERE id = $1', [contact_id]);
    const contact = contactResult.rows[0];
    const propResult = await pool.query('SELECT address FROM properties WHERE id = $1', [property_id]);
    const prop = propResult.rows[0];
    await logActivity('create', 'inquiry', row.id,
      `${contact?.first_name} ${contact?.last_name || ''} → ${prop?.address}`.trim(),
      null, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error creating inquiry:', err);
    res.status(500).json({ error: 'Failed to create inquiry' });
  }
});

app.put('/api/inquiries/:id', authenticate, async (req, res) => {
  try {
    const { status, interest_level, size_need, notes } = req.body;
    await pool.query('UPDATE inquiries SET status=$1, interest_level=$2, size_need=$3, notes=$4, updated_at=$5 WHERE id=$6',
      [status, interest_level, size_need, notes, now(), req.params.id]);
    const result = await pool.query('SELECT * FROM inquiries WHERE id = $1', [req.params.id]);
    const row = result.rows[0];
    await logActivity('update', 'inquiry', row.id, null, `Status: ${status}`, req.user.id);
    res.json(row);
  } catch (err) {
    console.error('Error updating inquiry:', err);
    res.status(500).json({ error: 'Failed to update inquiry' });
  }
});

app.delete('/api/inquiries/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM inquiries WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting inquiry:', err);
    res.status(500).json({ error: 'Failed to delete inquiry' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD / STATS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/stats', authenticate, async (req, res) => {
  try {
    const totalContactsResult = await pool.query('SELECT COUNT(*) as c FROM contacts');
    const totalPropertiesResult = await pool.query('SELECT COUNT(*) as c FROM properties');
    const activeListingsResult = await pool.query("SELECT COUNT(*) as c FROM properties WHERE is_listing = true AND status IN ('available','under_offer')");
    const activeDealsResult = await pool.query("SELECT COUNT(*) as c FROM deals WHERE stage NOT IN ('closed_won','closed_lost')");
    const closedWonResult = await pool.query("SELECT COUNT(*) as c FROM deals WHERE stage = 'closed_won'");

    const tasksDueTodayResult = await pool.query("SELECT COUNT(*) as c FROM tasks WHERE completed = false AND due_date = CURRENT_DATE");
    const tasksOverdueResult = await pool.query("SELECT COUNT(*) as c FROM tasks WHERE completed = false AND due_date < CURRENT_DATE AND due_date IS NOT NULL");
    const tasksUpcomingResult = await pool.query("SELECT COUNT(*) as c FROM tasks WHERE completed = false AND due_date > CURRENT_DATE AND due_date <= CURRENT_DATE + INTERVAL '7 days'");

    const dealsByStageResult = await pool.query(`
      SELECT stage, COUNT(*) as count,
      COALESCE(SUM(CAST(REPLACE(REPLACE(value,'$',''),',','') AS NUMERIC)),0) as total_value
      FROM deals WHERE stage NOT IN ('closed_won','closed_lost') GROUP BY stage
    `);

    const recentActivityResult = await pool.query(`
      SELECT a.*, u.name as user_name
      FROM activity_log a LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC LIMIT 20
    `);

    const upcomingTasksResult = await pool.query(`
      SELECT t.*, u.name as assigned_to_name
      FROM tasks t LEFT JOIN users u ON t.assigned_to = u.id
      WHERE t.completed = false
      ORDER BY CASE WHEN t.due_date IS NULL THEN 1 ELSE 0 END, t.due_date ASC
      LIMIT 10
    `);

    res.json({
      totalContacts: parseInt(totalContactsResult.rows[0].c),
      totalProperties: parseInt(totalPropertiesResult.rows[0].c),
      activeListings: parseInt(activeListingsResult.rows[0].c),
      activeDeals: parseInt(activeDealsResult.rows[0].c),
      closedWon: parseInt(closedWonResult.rows[0].c),
      tasksDueToday: parseInt(tasksDueTodayResult.rows[0].c),
      tasksOverdue: parseInt(tasksOverdueResult.rows[0].c),
      tasksUpcoming: parseInt(tasksUpcomingResult.rows[0].c),
      dealsByStage: dealsByStageResult.rows,
      recentActivity: recentActivityResult.rows,
      upcomingTasks: upcomingTasksResult.rows
    });
  } catch (err) {
    console.error('Error fetching stats:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ACTIVITY LOG
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/activity', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const result = await pool.query(`
      SELECT a.*, u.name as user_name
      FROM activity_log a LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC LIMIT $1
    `, [limit]);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching activity log:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL SEARCH
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/search', authenticate, async (req, res) => {
  try {
    const q = req.query.q;
    if (!q || q.length < 2) return res.json({ contacts: [], companies: [], properties: [], deals: [] });
    const like = `%${q}%`;

    const contactsResult = await pool.query(`
      SELECT id, first_name, last_name, email, phone, tags, 'contact' as _type
      FROM contacts WHERE first_name ILIKE $1 OR last_name ILIKE $2 OR email ILIKE $3 OR phone ILIKE $4 OR tags ILIKE $5 LIMIT 10
    `, [like, like, like, like, like]);

    const companiesResult = await pool.query(`
      SELECT id, name, type, 'company' as _type
      FROM companies WHERE name ILIKE $1 OR industry ILIKE $2 LIMIT 10
    `, [like, like]);

    const propertiesResult = await pool.query(`
      SELECT id, name, address, city, type, status, 'property' as _type
      FROM properties WHERE address ILIKE $1 OR name ILIKE $2 OR city ILIKE $3 OR submarket ILIKE $4 LIMIT 10
    `, [like, like, like, like]);

    const dealsResult = await pool.query(`
      SELECT id, title, stage, deal_type, 'deal' as _type
      FROM deals WHERE title ILIKE $1 LIMIT 10
    `, [like]);

    res.json({ contacts: contactsResult.rows, companies: companiesResult.rows, properties: propertiesResult.rows, deals: dealsResult.rows });
  } catch (err) {
    console.error('Error searching:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CSV EXPORT
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/export/:entity', authenticate, async (req, res) => {
  try {
    const entity = req.params.entity;
    let rows, filename;

    if (entity === 'contacts') {
      const result = await pool.query(`
        SELECT c.first_name, c.last_name, co.name as company, c.email, c.phone, c.tags, c.submarket, c.size_requirement, c.industry, c.notes, c.created_at
        FROM contacts c LEFT JOIN companies co ON c.company_id = co.id ORDER BY c.first_name
      `);
      rows = result.rows;
      filename = 'contacts_export.csv';
    } else if (entity === 'deals') {
      const result = await pool.query(`
        SELECT d.title, d.stage, d.deal_type, c.first_name || ' ' || COALESCE(c.last_name,'') as contact,
        p.address as property, d.value, d.close_date, u.name as assigned_to, d.notes, d.created_at
        FROM deals d LEFT JOIN contacts c ON d.contact_id = c.id LEFT JOIN properties p ON d.property_id = p.id
        LEFT JOIN users u ON d.assigned_to = u.id ORDER BY d.updated_at DESC
      `);
      rows = result.rows;
      filename = 'deals_export.csv';
    } else if (entity === 'properties') {
      const result = await pool.query(`
        SELECT p.name, p.address, p.city, p.state, p.submarket, p.type, p.size_sf, p.asking_rate, p.rate_type,
        p.status, p.is_listing, p.list_date, p.expiration_date, p.notes, p.created_at
        FROM properties p ORDER BY p.address
      `);
      rows = result.rows;
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
  } catch (err) {
    console.error('Error exporting:', err);
    res.status(500).json({ error: 'Export failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// AI CHAT PROXY
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/ai/chat', authenticate, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT claude_api_key FROM users WHERE id = $1', [req.user.id]);
    const user = userResult.rows[0];
    if (!user?.claude_api_key) return res.status(400).json({ error: 'No Claude API key configured. Add yours in Settings.' });

    // Gather CRM context for the AI
    const contactCountResult = await pool.query('SELECT COUNT(*) as c FROM contacts');
    const dealCountResult = await pool.query("SELECT COUNT(*) as c FROM deals WHERE stage NOT IN ('closed_won','closed_lost')");
    const listingCountResult = await pool.query("SELECT COUNT(*) as c FROM properties WHERE is_listing = true");

    const contactCount = parseInt(contactCountResult.rows[0].c);
    const dealCount = parseInt(dealCountResult.rows[0].c);
    const listingCount = parseInt(listingCountResult.rows[0].c);

    const { messages, context } = req.body;
    if (!messages || !messages.length) return res.status(400).json({ error: 'No messages provided' });

    let systemPrompt = `You are an AI assistant embedded in KM Team CRM, a commercial real estate CRM for brokers at Kidder Mathews specializing in the Seattle Eastside market (Bellevue, Kirkland, Redmond, Bothell, Woodinville, Issaqualmie, Snoqualmie, and north to Everett).

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
  } catch (err) {
    console.error('Error in AI chat:', err);
    res.status(500).json({ error: 'AI chat failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CSV IMPORT
// ═══════════════════════════════════════════════════════════════════════════════

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
      else inQuotes = !inQuotes;
    } else if (line[i] === ',' && !inQuotes) {
      result.push(current); current = '';
    } else {
      current += line[i];
    }
  }
  result.push(current);
  return result;
}

function parseCSV(text) {
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const headers = parseCSVLine(lines[0]).map(h => h.trim().replace(/^"|"$/g, ''));
  return lines.slice(1).filter(l => l.trim()).map(line => {
    const values = parseCSVLine(line);
    const obj = {};
    headers.forEach((h, i) => { obj[h] = (values[i] || '').trim().replace(/^"|"$/g, ''); });
    return obj;
  });
}

// Import Companies
app.post('/api/import/companies', authenticate, async (req, res) => {
  try {
    const { csv } = req.body;
    if (!csv) return res.status(400).json({ error: 'No CSV data provided' });
    const rows = parseCSV(csv);
    let imported = 0, skipped = 0, errors = [];

    for (const row of rows) {
      const name = (row['Company Name'] || '').trim();
      if (!name) { skipped++; continue; }
      const existing = await pool.query('SELECT id FROM companies WHERE name = $1', [name]);
      if (existing.rows.length > 0) { skipped++; continue; }
      try {
        await pool.query('INSERT INTO companies (name, address, city, state, created_by) VALUES ($1,$2,$3,$4,$5)',
          [name, row['Address Line 1'] || '', row['City'] || '', row['State'] || 'WA', req.user.id]);
        imported++;
      } catch (e) { errors.push(name); }
    }

    await logActivity('import', 'company', null, `${imported} companies imported`, null, req.user.id);
    res.json({ imported, skipped, errors: errors.length, total: rows.length });
  } catch (err) {
    console.error('Error importing companies:', err);
    res.status(500).json({ error: 'Import failed' });
  }
});

// Import Contacts
app.post('/api/import/contacts', authenticate, async (req, res) => {
  try {
    const { csv } = req.body;
    if (!csv) return res.status(400).json({ error: 'No CSV data provided' });
    const rows = parseCSV(csv);
    let imported = 0, skipped = 0, errors = [];

    for (const row of rows) {
      const firstName = (row['First Name'] || '').trim();
      if (!firstName) { skipped++; continue; }

      const existing = await pool.query(
        'SELECT id FROM contacts WHERE first_name = $1 AND last_name = $2 AND (phone = $3 OR email = $4)',
        [firstName, row['Last Name'] || '', row['Phone'] || '', row['Email Address'] || '']
      );
      if (existing.rows.length > 0) { skipped++; continue; }

      // Find or create company
      let companyId = null;
      const companyName = (row['Company Name'] || '').trim();
      if (companyName) {
        const co = await pool.query('SELECT id FROM companies WHERE name = $1', [companyName]);
        if (co.rows.length > 0) {
          companyId = co.rows[0].id;
        } else {
          const result = await pool.query('INSERT INTO companies (name, created_by) VALUES ($1,$2) RETURNING id', [companyName, req.user.id]);
          companyId = result.rows[0].id;
        }
      }

      // Build tags from Contact Type + Prospect Type
      const tagParts = [];
      if (row['Contact Type']) tagParts.push(row['Contact Type']);
      if (row['Prospect Type'] && row['Prospect Type'] !== row['Contact Type']) tagParts.push(row['Prospect Type']);
      const tags = tagParts.filter(Boolean).join(',');

      try {
        await pool.query(`INSERT INTO contacts
          (first_name, last_name, company_id, email, phone, tags, submarket, size_requirement, industry, notes, created_by)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [
            firstName,
            row['Last Name'] || '',
            companyId,
            row['Email Address'] || '',
            row['Phone'] || row['Mobile Phone'] || '',
            tags,
            row['Submarket'] || '',
            row['Estimated Size'] ? `${row['Estimated Size']} ${row['Size Type'] || 'SF'}`.trim() : '',
            row['Industry'] || '',
            row['Notes'] || '',
            req.user.id
          ]);
        imported++;
      } catch (e) { errors.push(`${firstName} ${row['Last Name'] || ''}`); }
    }

    await logActivity('import', 'contact', null, `${imported} contacts imported`, null, req.user.id);
    res.json({ imported, skipped, errors: errors.length, total: rows.length });
  } catch (err) {
    console.error('Error importing contacts:', err);
    res.status(500).json({ error: 'Import failed' });
  }
});

// Import Activities as Tasks
app.post('/api/import/activities', authenticate, async (req, res) => {
  try {
    const { csv } = req.body;
    if (!csv) return res.status(400).json({ error: 'No CSV data provided' });
    const rows = parseCSV(csv);
    let imported = 0, skipped = 0, errors = [];

    for (const row of rows) {
      const subject = (row['Subject'] || row['Activity Type'] || '').trim();
      if (!subject) { skipped++; continue; }

      // Find linked contact
      let contactId = null;
      const contactName = (row['Contact Name'] || '').trim();
      if (contactName) {
        const parts = contactName.split(' ');
        const c = await pool.query('SELECT id FROM contacts WHERE first_name = $1 AND last_name = $2',
          [parts[0] || '', parts.slice(1).join(' ') || '']);
        if (c.rows.length > 0) contactId = c.rows[0].id;
      }

      const isComplete = row['Is Complete'] === 'Yes' || row['Is Complete'] === '1';
      const priority = row['Activity Type'] === 'Task' ? 'high' : 'medium';
      const dueDate = row['Date'] || row['Completed Date'] || null;

      try {
        await pool.query(`INSERT INTO tasks (title, due_date, completed, priority, contact_id, notes, created_by)
          VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [subject, dueDate, isComplete, priority, contactId, row['Notes'] || '', req.user.id]);
        imported++;
      } catch (e) { errors.push(subject); }
    }

    await logActivity('import', 'task', null, `${imported} activities imported`, null, req.user.id);
    res.json({ imported, skipped, errors: errors.length, total: rows.length });
  } catch (err) {
    console.error('Error importing activities:', err);
    res.status(500).json({ error: 'Import failed' });
  }
});

// Import Properties
app.post('/api/import/properties', authenticate, async (req, res) => {
  try {
    const { csv } = req.body;
    if (!csv) return res.status(400).json({ error: 'No CSV data provided' });
    const rows = parseCSV(csv);
    let imported = 0, skipped = 0, errors = [];

    for (const row of rows) {
      const address = (row['Address Line 1'] || row['Property Name'] || '').trim();
      if (!address) { skipped++; continue; }
      const existing = await pool.query('SELECT id FROM properties WHERE address = $1 AND city = $2',
        [address, row['City'] || '']);
      if (existing.rows.length > 0) { skipped++; continue; }
      try {
        const sizeSf = parseInt((row['Size'] || '').replace(/,/g, '')) || null;
        await pool.query(`INSERT INTO properties (name, address, city, state, submarket, type, size_sf, notes, created_by)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            row['Property Name'] || '',
            address,
            row['City'] || '',
            row['State'] || 'WA',
            row['Submarket'] || '',
            (row['Asset Type'] || 'industrial').toLowerCase(),
            sizeSf,
            row['Notes'] || '',
            req.user.id
          ]);
        imported++;
      } catch (e) { errors.push(address); }
    }

    await logActivity('import', 'property', null, `${imported} properties imported`, null, req.user.id);
    res.json({ imported, skipped, errors: errors.length, total: rows.length });
  } catch (err) {
    console.error('Error importing properties:', err);
    res.status(500).json({ error: 'Import failed' });
  }
});

// Import Deals
app.post('/api/import/deals', authenticate, async (req, res) => {
  try {
    const { csv } = req.body;
    if (!csv) return res.status(400).json({ error: 'No CSV data provided' });
    const rows = parseCSV(csv);
    let imported = 0, skipped = 0, errors = [];

    // Stage mapping from CRE OneSource to our stages
    const stageMap = {
      'prospect': 'prospect', 'lead': 'prospect', 'new': 'prospect',
      'touring': 'touring', 'tour': 'touring', 'showing': 'touring',
      'loi': 'loi', 'letter of intent': 'loi', 'offer': 'loi',
      'negotiating': 'negotiating', 'negotiation': 'negotiating', 'under contract': 'negotiating',
      'closed': 'closed_won', 'closed won': 'closed_won', 'executed': 'closed_won', 'complete': 'closed_won',
      'dead': 'closed_lost', 'lost': 'closed_lost', 'closed lost': 'closed_lost', 'cancelled': 'closed_lost'
    };

    const dealTypeMap = {
      'tenant rep': 'lease_tenant', 'tenant representation': 'lease_tenant',
      'landlord rep': 'lease_landlord', 'landlord representation': 'lease_landlord',
      'sale': 'sale', 'disposition': 'sale', 'acquisition': 'sale',
      'sublease': 'sublease'
    };

    for (const row of rows) {
      const title = (row['Deal Name'] || '').trim();
      if (!title) { skipped++; continue; }
      const existing = await pool.query('SELECT id FROM deals WHERE title = $1', [title]);
      if (existing.rows.length > 0) { skipped++; continue; }

      // Find linked contact
      let contactId = null;
      const contactName = (row['Primary Contact Name'] || row['Tenant Name (Tenant Rep deals only)'] || '').trim();
      if (contactName) {
        const parts = contactName.trim().split(' ');
        const c = await pool.query('SELECT id FROM contacts WHERE first_name = $1 AND last_name = $2',
          [parts[0] || '', parts.slice(1).join(' ') || '']);
        if (c.rows.length > 0) contactId = c.rows[0].id;
      }

      // Find linked property
      let propertyId = null;
      const propName = (row['Property Name (Disposition or LLA deals only)'] || '').trim();
      if (propName) {
        const p = await pool.query('SELECT id FROM properties WHERE name = $1 OR address = $2', [propName, propName]);
        if (p.rows.length > 0) propertyId = p.rows[0].id;
      }

      const rawStage = (row['Stage'] || row['Deal Status'] || 'prospect').toLowerCase();
      const stage = stageMap[rawStage] || 'prospect';
      const rawType = (row['Deal Type'] || '').toLowerCase();
      const dealType = dealTypeMap[rawType] || 'lease_tenant';
      const value = row['Estimated Transaction Value'] || row['Actual Transaction Value'] || '';
      const closeDate = row['Estimated Close Date'] || row['Actual Close Date'] || null;

      try {
        await pool.query(`INSERT INTO deals (title, stage, deal_type, contact_id, property_id, value, close_date, notes, assigned_to, created_by)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [title, stage, dealType, contactId, propertyId, value, closeDate, row['Notes'] || '', req.user.id, req.user.id]);
        imported++;
      } catch (e) { errors.push(title); }
    }

    await logActivity('import', 'deal', null, `${imported} deals imported`, null, req.user.id);
    res.json({ imported, skipped, errors: errors.length, total: rows.length });
  } catch (err) {
    console.error('Error importing deals:', err);
    res.status(500).json({ error: 'Import failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SPA FALLBACK — checks public/index.html then root index.html
// ═══════════════════════════════════════════════════════════════════════════════
app.get('*', (req, res) => {
  const publicHtml = path.join(__dirname, 'public', 'index.html');
  const rootHtml = path.join(__dirname, 'index.html');
  if (fs.existsSync(publicHtml)) {
    res.sendFile(publicHtml);
  } else if (fs.existsSync(rootHtml)) {
    res.sendFile(rootHtml);
  } else {
    res.status(404).send('index.html not found. Make sure it is in the root or public/ folder.');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════════════════════
(async () => {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`\n  🏢 KM Team CRM running at http://localhost:${PORT}\n`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();
