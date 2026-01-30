const express = require('express');
const { Pool } = require('pg');
const { nanoid } = require('nanoid');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// File upload config
const upload = multer({ 
  dest: '/data/uploads/',
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB
});

// Ensure upload dir exists
if (!fs.existsSync('/data/uploads')) {
  fs.mkdirSync('/data/uploads', { recursive: true });
}

// Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@db:5432/handoff'
});

// SSO Auth middleware - validates session against auth.jdms.nl
async function requireAuth(req, res, next) {
  const sessionToken = req.cookies['__Secure-next-auth.session-token'] || 
                       req.cookies['next-auth.session-token'];
  
  if (!sessionToken) {
    // For API calls, return 401
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    // For page requests, redirect to auth
    const callbackUrl = encodeURIComponent(`https://handoff.jdms.nl${req.originalUrl}`);
    return res.redirect(`https://auth.jdms.nl/login?callbackUrl=${callbackUrl}`);
  }

  try {
    const response = await fetch('https://auth.jdms.nl/api/validate', {
      headers: { Cookie: `__Secure-next-auth.session-token=${sessionToken}` }
    });
    const data = await response.json();

    if (data.valid) {
      req.user = data.user;
      return next();
    }
  } catch (error) {
    console.error('Auth validation error:', error.message);
  }

  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Invalid session' });
  }
  const callbackUrl = encodeURIComponent(`https://handoff.jdms.nl${req.originalUrl}`);
  res.redirect(`https://auth.jdms.nl/login?callbackUrl=${callbackUrl}`);
}

// Client auth middleware (magic link - kept for client portal access)
function clientAuth(req, res, next) {
  const token = req.query.token || req.headers['x-client-token'];
  if (!token) return res.status(401).json({ error: 'No access token' });
  
  pool.query('SELECT * FROM clients WHERE access_token = $1', [token])
    .then(result => {
      if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid token' });
      req.client = result.rows[0];
      pool.query('UPDATE clients SET last_seen_at = NOW() WHERE id = $1', [req.client.id]);
      next();
    })
    .catch(() => res.status(500).json({ error: 'Auth failed' }));
}

// Initialize database
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS portals (
      id VARCHAR(12) PRIMARY KEY,
      user_id TEXT NOT NULL,
      subdomain VARCHAR(50) UNIQUE NOT NULL,
      name VARCHAR(255) NOT NULL,
      logo_url TEXT,
      accent_color VARCHAR(7) DEFAULT '#6366f1',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS clients (
      id VARCHAR(12) PRIMARY KEY,
      portal_id VARCHAR(12) REFERENCES portals(id) ON DELETE CASCADE,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL,
      access_token VARCHAR(64) UNIQUE NOT NULL,
      last_seen_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(portal_id, email)
    );

    CREATE TABLE IF NOT EXISTS projects (
      id VARCHAR(12) PRIMARY KEY,
      client_id VARCHAR(12) REFERENCES clients(id) ON DELETE CASCADE,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      status VARCHAR(20) DEFAULT 'active',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id VARCHAR(12) PRIMARY KEY,
      project_id VARCHAR(12) REFERENCES projects(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      stage VARCHAR(20) DEFAULT 'backlog',
      position INT DEFAULT 0,
      due_date DATE,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS updates (
      id VARCHAR(12) PRIMARY KEY,
      project_id VARCHAR(12) REFERENCES projects(id) ON DELETE CASCADE,
      author_type VARCHAR(10) NOT NULL,
      author_id TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS files (
      id VARCHAR(12) PRIMARY KEY,
      project_id VARCHAR(12) REFERENCES projects(id) ON DELETE CASCADE,
      update_id VARCHAR(12) REFERENCES updates(id),
      name VARCHAR(255) NOT NULL,
      file_path TEXT NOT NULL,
      file_size BIGINT,
      mime_type VARCHAR(100),
      uploaded_by TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS file_downloads (
      id VARCHAR(12) PRIMARY KEY,
      file_id VARCHAR(12) REFERENCES files(id) ON DELETE CASCADE,
      client_id VARCHAR(12) REFERENCES clients(id),
      ip_address VARCHAR(45),
      downloaded_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS client_views (
      id VARCHAR(12) PRIMARY KEY,
      client_id VARCHAR(12) REFERENCES clients(id) ON DELETE CASCADE,
      project_id VARCHAR(12) REFERENCES projects(id),
      page VARCHAR(50),
      viewed_at TIMESTAMP DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_clients_token ON clients(access_token);
    CREATE INDEX IF NOT EXISTS idx_portals_user ON portals(user_id);
  `);
  console.log('Database initialized');
}

// ==================== AUTH ROUTES ====================

// Get current user (from SSO)
app.get('/api/auth/me', requireAuth, async (req, res) => {
  res.json(req.user);
});

// ==================== PORTAL ROUTES ====================

// Create portal (user-scoped)
app.post('/api/portals', requireAuth, async (req, res) => {
  try {
    const { subdomain, name, logo_url, accent_color } = req.body;
    const id = nanoid(12);
    
    await pool.query(
      'INSERT INTO portals (id, user_id, subdomain, name, logo_url, accent_color) VALUES ($1, $2, $3, $4, $5, $6)',
      [id, req.user.id, subdomain, name, logo_url, accent_color || '#6366f1']
    );
    
    res.json({ id, subdomain });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Subdomain taken' });
    res.status(500).json({ error: 'Failed to create portal' });
  }
});

// Get user's portals (user-scoped)
app.get('/api/portals', requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT p.*, COUNT(c.id) as client_count 
     FROM portals p LEFT JOIN clients c ON p.id = c.portal_id 
     WHERE p.user_id = $1 GROUP BY p.id ORDER BY p.created_at DESC`,
    [req.user.id]
  );
  res.json(result.rows);
});

// Get portal by subdomain (public for client access)
app.get('/api/portals/by-subdomain/:subdomain', async (req, res) => {
  const result = await pool.query(
    'SELECT id, subdomain, name, logo_url, accent_color FROM portals WHERE subdomain = $1',
    [req.params.subdomain]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: 'Portal not found' });
  res.json(result.rows[0]);
});

// ==================== CLIENT ROUTES ====================

// Create client (verify portal ownership)
app.post('/api/portals/:portalId/clients', requireAuth, async (req, res) => {
  try {
    // Verify user owns this portal
    const portal = await pool.query('SELECT id FROM portals WHERE id = $1 AND user_id = $2', [req.params.portalId, req.user.id]);
    if (portal.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

    const { name, email } = req.body;
    const id = nanoid(12);
    const accessToken = nanoid(64);
    
    await pool.query(
      'INSERT INTO clients (id, portal_id, name, email, access_token) VALUES ($1, $2, $3, $4, $5)',
      [id, req.params.portalId, name, email, accessToken]
    );
    
    res.json({ id, accessToken, portalUrl: `/portal?token=${accessToken}` });
  } catch (e) {
    res.status(500).json({ error: 'Failed to create client' });
  }
});

// Get portal clients (verify ownership)
app.get('/api/portals/:portalId/clients', requireAuth, async (req, res) => {
  const portal = await pool.query('SELECT id FROM portals WHERE id = $1 AND user_id = $2', [req.params.portalId, req.user.id]);
  if (portal.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  const result = await pool.query(
    `SELECT c.*, COUNT(p.id) as project_count 
     FROM clients c LEFT JOIN projects p ON c.id = p.client_id 
     WHERE c.portal_id = $1 GROUP BY c.id ORDER BY c.created_at DESC`,
    [req.params.portalId]
  );
  res.json(result.rows);
});

// ==================== PROJECT ROUTES ====================

// Create project (verify ownership chain)
app.post('/api/clients/:clientId/projects', requireAuth, async (req, res) => {
  // Verify ownership: user -> portal -> client
  const check = await pool.query(
    `SELECT c.id FROM clients c 
     JOIN portals p ON c.portal_id = p.id 
     WHERE c.id = $1 AND p.user_id = $2`,
    [req.params.clientId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  const { name, description } = req.body;
  const id = nanoid(12);
  
  await pool.query(
    'INSERT INTO projects (id, client_id, name, description) VALUES ($1, $2, $3, $4)',
    [id, req.params.clientId, name, description]
  );
  
  res.json({ id });
});

// Get client projects
app.get('/api/clients/:clientId/projects', requireAuth, async (req, res) => {
  const check = await pool.query(
    `SELECT c.id FROM clients c JOIN portals p ON c.portal_id = p.id WHERE c.id = $1 AND p.user_id = $2`,
    [req.params.clientId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  const result = await pool.query(
    'SELECT * FROM projects WHERE client_id = $1 ORDER BY created_at DESC',
    [req.params.clientId]
  );
  res.json(result.rows);
});

// Get project with tasks
app.get('/api/projects/:projectId', requireAuth, async (req, res) => {
  const check = await pool.query(
    `SELECT pr.* FROM projects pr 
     JOIN clients c ON pr.client_id = c.id 
     JOIN portals p ON c.portal_id = p.id 
     WHERE pr.id = $1 AND p.user_id = $2`,
    [req.params.projectId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  
  const tasks = await pool.query('SELECT * FROM tasks WHERE project_id = $1 ORDER BY position', [req.params.projectId]);
  
  res.json({ ...check.rows[0], tasks: tasks.rows });
});

// ==================== TASK ROUTES ====================

// Create task
app.post('/api/projects/:projectId/tasks', requireAuth, async (req, res) => {
  const check = await pool.query(
    `SELECT pr.id FROM projects pr JOIN clients c ON pr.client_id = c.id JOIN portals p ON c.portal_id = p.id WHERE pr.id = $1 AND p.user_id = $2`,
    [req.params.projectId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  const { title, description, stage, due_date } = req.body;
  const id = nanoid(12);
  
  await pool.query(
    'INSERT INTO tasks (id, project_id, title, description, stage, due_date) VALUES ($1, $2, $3, $4, $5, $6)',
    [id, req.params.projectId, title, description, stage || 'backlog', due_date]
  );
  
  res.json({ id });
});

// Update task
app.patch('/api/tasks/:taskId', requireAuth, async (req, res) => {
  // Verify ownership
  const check = await pool.query(
    `SELECT t.id FROM tasks t JOIN projects pr ON t.project_id = pr.id JOIN clients c ON pr.client_id = c.id JOIN portals p ON c.portal_id = p.id WHERE t.id = $1 AND p.user_id = $2`,
    [req.params.taskId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  const { title, description, stage, position, due_date } = req.body;
  const updates = [];
  const values = [];
  let i = 1;
  
  if (title) { updates.push(`title = $${i++}`); values.push(title); }
  if (description !== undefined) { updates.push(`description = $${i++}`); values.push(description); }
  if (stage) { updates.push(`stage = $${i++}`); values.push(stage); }
  if (position !== undefined) { updates.push(`position = $${i++}`); values.push(position); }
  if (due_date !== undefined) { updates.push(`due_date = $${i++}`); values.push(due_date); }
  
  if (updates.length === 0) return res.json({ success: true });
  
  values.push(req.params.taskId);
  await pool.query(`UPDATE tasks SET ${updates.join(', ')} WHERE id = $${i}`, values);
  
  res.json({ success: true });
});

// Delete task
app.delete('/api/tasks/:taskId', requireAuth, async (req, res) => {
  const check = await pool.query(
    `SELECT t.id FROM tasks t JOIN projects pr ON t.project_id = pr.id JOIN clients c ON pr.client_id = c.id JOIN portals p ON c.portal_id = p.id WHERE t.id = $1 AND p.user_id = $2`,
    [req.params.taskId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  await pool.query('DELETE FROM tasks WHERE id = $1', [req.params.taskId]);
  res.json({ success: true });
});

// ==================== UPDATES ROUTES ====================

app.post('/api/projects/:projectId/updates', requireAuth, async (req, res) => {
  const check = await pool.query(
    `SELECT pr.id FROM projects pr JOIN clients c ON pr.client_id = c.id JOIN portals p ON c.portal_id = p.id WHERE pr.id = $1 AND p.user_id = $2`,
    [req.params.projectId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  const { content } = req.body;
  const id = nanoid(12);
  
  await pool.query(
    'INSERT INTO updates (id, project_id, author_type, author_id, content) VALUES ($1, $2, $3, $4, $5)',
    [id, req.params.projectId, 'user', req.user.id, content]
  );
  
  res.json({ id });
});

app.get('/api/projects/:projectId/updates', requireAuth, async (req, res) => {
  const check = await pool.query(
    `SELECT pr.id FROM projects pr JOIN clients c ON pr.client_id = c.id JOIN portals p ON c.portal_id = p.id WHERE pr.id = $1 AND p.user_id = $2`,
    [req.params.projectId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  const result = await pool.query(
    `SELECT u.*, c.name as client_name FROM updates u 
     LEFT JOIN clients c ON u.author_type = 'client' AND u.author_id = c.id
     WHERE u.project_id = $1 ORDER BY u.created_at DESC`,
    [req.params.projectId]
  );
  res.json(result.rows);
});

// ==================== FILE ROUTES ====================

app.post('/api/projects/:projectId/files', requireAuth, upload.single('file'), async (req, res) => {
  const check = await pool.query(
    `SELECT pr.id FROM projects pr JOIN clients c ON pr.client_id = c.id JOIN portals p ON c.portal_id = p.id WHERE pr.id = $1 AND p.user_id = $2`,
    [req.params.projectId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  if (!req.file) return res.status(400).json({ error: 'No file' });
  
  const id = nanoid(12);
  await pool.query(
    'INSERT INTO files (id, project_id, name, file_path, file_size, mime_type, uploaded_by) VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [id, req.params.projectId, req.file.originalname, req.file.path, req.file.size, req.file.mimetype, req.user.id]
  );
  
  res.json({ id, name: req.file.originalname });
});

app.get('/api/projects/:projectId/files', requireAuth, async (req, res) => {
  const check = await pool.query(
    `SELECT pr.id FROM projects pr JOIN clients c ON pr.client_id = c.id JOIN portals p ON c.portal_id = p.id WHERE pr.id = $1 AND p.user_id = $2`,
    [req.params.projectId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  const result = await pool.query(
    `SELECT f.*, COUNT(fd.id) as download_count FROM files f 
     LEFT JOIN file_downloads fd ON f.id = fd.file_id
     WHERE f.project_id = $1 GROUP BY f.id ORDER BY f.created_at DESC`,
    [req.params.projectId]
  );
  res.json(result.rows);
});

// Download file (client access via magic link)
app.get('/api/files/:fileId/download', clientAuth, async (req, res) => {
  const file = await pool.query('SELECT * FROM files WHERE id = $1', [req.params.fileId]);
  if (file.rows.length === 0) return res.status(404).json({ error: 'File not found' });
  
  await pool.query(
    'INSERT INTO file_downloads (id, file_id, client_id, ip_address) VALUES ($1, $2, $3, $4)',
    [nanoid(12), req.params.fileId, req.client.id, req.ip]
  );
  
  res.download(file.rows[0].file_path, file.rows[0].name);
});

// ==================== CLIENT PORTAL ROUTES (magic link access) ====================

app.get('/api/portal/projects', clientAuth, async (req, res) => {
  await pool.query('INSERT INTO client_views (id, client_id, page) VALUES ($1, $2, $3)', [nanoid(12), req.client.id, 'projects']);
  
  const result = await pool.query('SELECT * FROM projects WHERE client_id = $1 ORDER BY created_at DESC', [req.client.id]);
  res.json(result.rows);
});

app.get('/api/portal/projects/:projectId', clientAuth, async (req, res) => {
  await pool.query('INSERT INTO client_views (id, client_id, project_id, page) VALUES ($1, $2, $3, $4)', [nanoid(12), req.client.id, req.params.projectId, 'project']);
  
  const project = await pool.query('SELECT * FROM projects WHERE id = $1 AND client_id = $2', [req.params.projectId, req.client.id]);
  if (project.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  
  const tasks = await pool.query('SELECT id, title, stage, due_date FROM tasks WHERE project_id = $1 ORDER BY position', [req.params.projectId]);
  const updates = await pool.query(
    `SELECT u.id, u.content, u.created_at, u.author_type, c.name as client_name FROM updates u 
     LEFT JOIN clients c ON u.author_type = 'client' AND u.author_id = c.id
     WHERE u.project_id = $1 ORDER BY u.created_at DESC LIMIT 10`,
    [req.params.projectId]
  );
  const files = await pool.query('SELECT id, name, file_size, created_at FROM files WHERE project_id = $1 ORDER BY created_at DESC', [req.params.projectId]);
  
  res.json({ ...project.rows[0], tasks: tasks.rows, updates: updates.rows, files: files.rows });
});

app.post('/api/portal/projects/:projectId/updates', clientAuth, async (req, res) => {
  const project = await pool.query('SELECT id FROM projects WHERE id = $1 AND client_id = $2', [req.params.projectId, req.client.id]);
  if (project.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });
  
  const { content } = req.body;
  const id = nanoid(12);
  
  await pool.query(
    'INSERT INTO updates (id, project_id, author_type, author_id, content) VALUES ($1, $2, $3, $4, $5)',
    [id, req.params.projectId, 'client', req.client.id, content]
  );
  
  res.json({ id });
});

// ==================== ANALYTICS ====================

app.get('/api/clients/:clientId/activity', requireAuth, async (req, res) => {
  const check = await pool.query(
    `SELECT c.id FROM clients c JOIN portals p ON c.portal_id = p.id WHERE c.id = $1 AND p.user_id = $2`,
    [req.params.clientId, req.user.id]
  );
  if (check.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });

  const views = await pool.query('SELECT * FROM client_views WHERE client_id = $1 ORDER BY viewed_at DESC LIMIT 50', [req.params.clientId]);
  const downloads = await pool.query(
    `SELECT fd.*, f.name as file_name FROM file_downloads fd JOIN files f ON fd.file_id = f.id WHERE fd.client_id = $1 ORDER BY fd.downloaded_at DESC LIMIT 50`,
    [req.params.clientId]
  );
  
  res.json({ views: views.rows, downloads: downloads.rows });
});

// ==================== STATIC FILES ====================

// Protected dashboard
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Client portal (public with token)
app.get('/portal', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'portal.html'));
});

app.use(express.static('public'));

// ==================== START ====================

const PORT = process.env.PORT || 3000;

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Handoff running on port ${PORT}`);
  });
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
