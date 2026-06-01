const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 5000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// ── Database ────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ── Helpers ─────────────────────────────────────────────────────────────────
function hashPassword(password) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(password).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// In-memory session store (sufficient for small user base)
const sessions = new Map();

function createSession(userId, firmId, role, name) {
  const token = generateToken();
  sessions.set(token, {
    userId, firmId, role, name,
    createdAt: Date.now(),
    expiresAt: Date.now() + 8 * 60 * 60 * 1000 // 8 hours
  });
  return token;
}

function getSession(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) { sessions.delete(token); return null; }
  return session;
}

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'];
  const session = getSession(token);
  if (!session) return res.status(401).json({ error: 'No autorizado' });
  req.session = session;
  next();
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-session-token'];
  const session = getSession(token);
  if (!session) return res.status(401).json({ error: 'No autorizado' });
  if (session.role !== 'superadmin' && session.role !== 'firm_admin') {
    return res.status(403).json({ error: 'Acceso denegado' });
  }
  req.session = session;
  next();
}

function requireSuperAdmin(req, res, next) {
  const token = req.headers['x-session-token'];
  const session = getSession(token);
  if (!session || session.role !== 'superadmin') {
    return res.status(403).json({ error: 'Solo superadmin' });
  }
  req.session = session;
  next();
}

app.use(express.json({ limit: '10mb' }));

// ── Serve static files first ────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── DB Init ──────────────────────────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS firms (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        code TEXT UNIQUE NOT NULL,
        active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        firm_id INTEGER REFERENCES firms(id),
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'preparer',
        active BOOLEAN DEFAULT true,
        must_change_password BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        firm_id INTEGER REFERENCES firms(id),
        name TEXT NOT NULL,
        country TEXT DEFAULT '',
        ground_type TEXT DEFAULT '',
        data JSONB NOT NULL DEFAULT '{}',
        saved_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Seed superadmin if not exists
    const existing = await client.query("SELECT id FROM users WHERE email = $1", ['juliangaviria29@gmail.com']);
    if (existing.rows.length === 0) {
      // Create superadmin firm
      const firmRes = await client.query(
        "INSERT INTO firms (name, code) VALUES ($1, $2) ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name RETURNING id",
        ['LexAsylum Admin', 'LEXADMIN']
      );
      const firmId = firmRes.rows[0].id;

      await client.query(
        "INSERT INTO users (firm_id, name, email, password_hash, role, must_change_password) VALUES ($1, $2, $3, $4, $5, $6)",
        [firmId, 'Julian Gaviria', 'juliangaviria29@gmail.com', hashPassword('Julian1994'), 'superadmin', true]
      );
      console.log('✅ Superadmin created');
    }

    // Seed first firm if not exists
    const firm1 = await client.query("SELECT id FROM firms WHERE code = $1", ['HBERNAL']);
    let firm1Id;
    if (firm1.rows.length === 0) {
      const f = await client.query(
        "INSERT INTO firms (name, code) VALUES ($1, $2) RETURNING id",
        ['Hernando Bernal Jr', 'HBERNAL']
      );
      firm1Id = f.rows[0].id;
      console.log('✅ First firm created');
    } else {
      firm1Id = firm1.rows[0].id;
    }

    const user1 = await client.query("SELECT id FROM users WHERE email = $1", ['marlon@hbernallaw.com']);
    if (user1.rows.length === 0) {
      await client.query(
        "INSERT INTO users (firm_id, name, email, password_hash, role, must_change_password) VALUES ($1, $2, $3, $4, $5, $6)",
        [firm1Id, 'Marlon Pasaje', 'marlon@hbernallaw.com', hashPassword('Marlon2025!'), 'preparer', true]
      );
      console.log('✅ First user created — temp password: Marlon2025!');
    }

    console.log('✅ Database ready');
  } finally {
    client.release();
  }
}

// ── AUTH ENDPOINTS ───────────────────────────────────────────────────────────

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

  try {
    const result = await pool.query(
      `SELECT u.*, f.name as firm_name, f.code as firm_code
       FROM users u JOIN firms f ON u.firm_id = f.id
       WHERE u.email = $1 AND u.active = true AND f.active = true`,
      [email.toLowerCase().trim()]
    );

    if (result.rows.length === 0) return res.status(401).json({ error: 'Credenciales incorrectas' });

    const user = result.rows[0];
    if (user.password_hash !== hashPassword(password)) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const token = createSession(user.id, user.firm_id, user.role, user.name);

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        firmId: user.firm_id,
        firmName: user.firm_name,
        firmCode: user.firm_code,
        mustChangePassword: user.must_change_password,
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

// Change password
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  }
  try {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
    if (user.rows[0].password_hash !== hashPassword(currentPassword)) {
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }
    await pool.query(
      'UPDATE users SET password_hash = $1, must_change_password = false WHERE id = $2',
      [hashPassword(newPassword), req.session.userId]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Verify session
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.role, u.must_change_password,
              f.id as firm_id, f.name as firm_name, f.code as firm_code
       FROM users u JOIN firms f ON u.firm_id = f.id WHERE u.id = $1`,
      [req.session.userId]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });
    const u = result.rows[0];
    res.json({
      id: u.id, name: u.name, email: u.email, role: u.role,
      firmId: u.firm_id, firmName: u.firm_name, firmCode: u.firm_code,
      mustChangePassword: u.must_change_password,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── CASES ENDPOINTS ──────────────────────────────────────────────────────────

// Get cases (user sees own, firm_admin sees firm, superadmin sees all)
app.get('/api/cases', requireAuth, async (req, res) => {
  try {
    let query, params;
    if (req.session.role === 'superadmin') {
      query = `SELECT c.*, u.name as user_name, f.name as firm_name
               FROM cases c JOIN users u ON c.user_id = u.id JOIN firms f ON c.firm_id = f.id
               ORDER BY c.updated_at DESC`;
      params = [];
    } else if (req.session.role === 'firm_admin') {
      query = `SELECT c.*, u.name as user_name, f.name as firm_name
               FROM cases c JOIN users u ON c.user_id = u.id JOIN firms f ON c.firm_id = f.id
               WHERE c.firm_id = $1 ORDER BY c.updated_at DESC`;
      params = [req.session.firmId];
    } else {
      query = `SELECT c.*, u.name as user_name, f.name as firm_name
               FROM cases c JOIN users u ON c.user_id = u.id JOIN firms f ON c.firm_id = f.id
               WHERE c.user_id = $1 ORDER BY c.updated_at DESC`;
      params = [req.session.userId];
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Save/update case
app.post('/api/cases', requireAuth, async (req, res) => {
  const { id, name, country, groundType, data } = req.body;
  if (!id || !name) return res.status(400).json({ error: 'id y name requeridos' });

  try {
    await pool.query(
      `INSERT INTO cases (id, user_id, firm_id, name, country, ground_type, data, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         country = EXCLUDED.country,
         ground_type = EXCLUDED.ground_type,
         data = EXCLUDED.data,
         updated_at = NOW()`,
      [id, req.session.userId, req.session.firmId, name, country || '', groundType || '', JSON.stringify(data || {})]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete case
app.delete('/api/cases/:id', requireAuth, async (req, res) => {
  try {
    const check = await pool.query('SELECT user_id, firm_id FROM cases WHERE id = $1', [req.params.id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Caso no encontrado' });

    const c = check.rows[0];
    const canDelete = req.session.role === 'superadmin' ||
      (req.session.role === 'firm_admin' && c.firm_id === req.session.firmId) ||
      c.user_id === req.session.userId;

    if (!canDelete) return res.status(403).json({ error: 'Sin permiso' });

    await pool.query('DELETE FROM cases WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN ENDPOINTS (superadmin only) ────────────────────────────────────────

// Get all firms
app.get('/api/admin/firms', requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT f.*, COUNT(u.id) as user_count, COUNT(c.id) as case_count
      FROM firms f
      LEFT JOIN users u ON u.firm_id = f.id AND u.active = true
      LEFT JOIN cases c ON c.firm_id = f.id
      GROUP BY f.id ORDER BY f.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create firm
app.post('/api/admin/firms', requireSuperAdmin, async (req, res) => {
  const { name, code } = req.body;
  if (!name || !code) return res.status(400).json({ error: 'nombre y código requeridos' });
  try {
    const result = await pool.query(
      'INSERT INTO firms (name, code) VALUES ($1, $2) RETURNING *',
      [name, code.toUpperCase()]
    );
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Código de firma ya existe' });
    res.status(500).json({ error: err.message });
  }
});

// Toggle firm active
app.patch('/api/admin/firms/:id', requireSuperAdmin, async (req, res) => {
  const { active, name } = req.body;
  try {
    const updates = [];
    const params = [];
    if (active !== undefined) { updates.push(`active = $${params.length+1}`); params.push(active); }
    if (name) { updates.push(`name = $${params.length+1}`); params.push(name); }
    params.push(req.params.id);
    await pool.query(`UPDATE firms SET ${updates.join(', ')} WHERE id = $${params.length}`, params);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get users (superadmin sees all, firm_admin sees own firm)
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    let query, params;
    if (req.session.role === 'superadmin') {
      query = `SELECT u.id, u.name, u.email, u.role, u.active, u.must_change_password,
                      u.created_at, f.name as firm_name, f.code as firm_code, f.id as firm_id
               FROM users u JOIN firms f ON u.firm_id = f.id ORDER BY f.name, u.name`;
      params = [];
    } else {
      query = `SELECT u.id, u.name, u.email, u.role, u.active, u.must_change_password,
                      u.created_at, f.name as firm_name, f.code as firm_code, f.id as firm_id
               FROM users u JOIN firms f ON u.firm_id = f.id
               WHERE u.firm_id = $1 ORDER BY u.name`;
      params = [req.session.firmId];
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create user
app.post('/api/admin/users', requireSuperAdmin, async (req, res) => {
  const { firmId, name, email, password, role } = req.body;
  if (!firmId || !name || !email || !password) {
    return res.status(400).json({ error: 'firmId, nombre, email y contraseña requeridos' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO users (firm_id, name, email, password_hash, role, must_change_password)
       VALUES ($1, $2, $3, $4, $5, true) RETURNING id, name, email, role`,
      [firmId, name, email.toLowerCase().trim(), hashPassword(password), role || 'preparer']
    );
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email ya registrado' });
    res.status(500).json({ error: err.message });
  }
});

// Update user (toggle active, reset password, change role)
app.patch('/api/admin/users/:id', requireSuperAdmin, async (req, res) => {
  const { active, password, role, name } = req.body;
  try {
    const updates = [];
    const params = [];
    if (active !== undefined) { updates.push(`active = $${params.length+1}`); params.push(active); }
    if (password) {
      updates.push(`password_hash = $${params.length+1}`); params.push(hashPassword(password));
      updates.push(`must_change_password = $${params.length+1}`); params.push(true);
    }
    if (role) { updates.push(`role = $${params.length+1}`); params.push(role); }
    if (name) { updates.push(`name = $${params.length+1}`); params.push(name); }
    if (updates.length === 0) return res.status(400).json({ error: 'Nada que actualizar' });
    params.push(req.params.id);
    await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${params.length}`, params);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Dashboard stats (superadmin)
app.get('/api/admin/stats', requireSuperAdmin, async (req, res) => {
  try {
    const [firms, users, cases] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM firms WHERE active = true'),
      pool.query('SELECT COUNT(*) FROM users WHERE active = true'),
      pool.query('SELECT COUNT(*) FROM cases'),
    ]);
    res.json({
      firms: parseInt(firms.rows[0].count),
      users: parseInt(users.rows[0].count),
      cases: parseInt(cases.rows[0].count),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ANTHROPIC PROXY (requires auth) ─────────────────────────────────────────
app.post('/api/claude', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: { message: 'ANTHROPIC_API_KEY no configurada.' } });
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'web-search-2025-03-05'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(500).json({ error: { message: 'Error: ' + err.message } });
  }
});

app.post('/api/claude-stream', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    res.write(`data: ${JSON.stringify({ error: 'ANTHROPIC_API_KEY no configurada.' })}\n\n`);
    return res.end();
  }
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  try {
    const body = { ...req.body, stream: true };
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'web-search-2025-03-05'
      },
      body: JSON.stringify(body)
    });
    if (!response.ok) {
      const err = await response.json();
      res.write(`data: ${JSON.stringify({ error: err.error?.message || 'Error de Anthropic' })}\n\n`);
      return res.end();
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') continue;
        try {
          const event = JSON.parse(data);
          if (event.type === 'content_block_delta') {
            if (event.delta?.type === 'text_delta' && event.delta.text)
              res.write(`data: ${JSON.stringify({ text: event.delta.text })}\n\n`);
            if (event.delta?.type === 'input_json_delta' && event.delta.partial_json)
              res.write(`data: ${JSON.stringify({ text: event.delta.partial_json })}\n\n`);
          }
          if (event.type === 'content_block_start') {
            const block = event.content_block;
            if (block?.type === 'tool_result' && block?.content) {
              const toolText = block.content.filter(c=>c.type==='text').map(c=>c.text).join('');
              if (toolText) res.write(`data: ${JSON.stringify({ text: toolText })}\n\n`);
            }
          }
          if (event.type === 'message_stop')
            res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
        } catch(e) {}
      }
    }
    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (err) {
    res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
    res.end();
  }
});

// ── Catch-all: serve index.html for any non-API route ───────────────────────
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`LexAsylum corriendo en puerto ${PORT}`));
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
