import express from "express";
import cors from "cors";
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
// Configure CORS: allow all by default, or restrict to FRONTEND_URL when provided
const FRONTEND_URL = process.env.FRONTEND_URL;
if (FRONTEND_URL) {
	app.use(cors({ origin: FRONTEND_URL }));
	console.log('CORS restricted to', FRONTEND_URL);
} else {
	app.use(cors());
	console.log('CORS: allowing all origins (no FRONTEND_URL set)');
}
app.use(express.json());

const PORT = process.env.PORT || 5000;

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10');

// Database pool (expects DATABASE_URL in env)
const DATABASE_URL = process.env.DATABASE_URL;
let pool = null;
if (DATABASE_URL) {
	pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
} else {
	console.warn('Warning: DATABASE_URL not set. DB calls will fail until configured.');
}

// Seed a default admin user if none exists (useful for first run)
async function seedAdmin() {
	if (!pool) return;
	try {
		const r = await pool.query("SELECT id FROM users WHERE email='admin@duoc.cl' LIMIT 1");
		if (r.rowCount === 0) {
			const hash = await bcrypt.hash('admin123', BCRYPT_ROUNDS);
			await pool.query('INSERT INTO users(name,email,password_hash,is_admin) VALUES($1,$2,$3,$4)', ['admin', 'admin@duoc.cl', hash, true]);
			console.log('Admin user created: admin@duoc.cl / admin123');
		}
	} catch (err) {
		console.error('Seed admin error (DB may not be ready):', err.message);
	}
}

seedAdmin();

function authMiddleware(req, res, next) {
	const auth = req.headers.authorization;
	if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
	const token = auth.split(' ')[1];
	try {
		const payload = jwt.verify(token, process.env.JWT_SECRET || 'devsecret');
		req.user = payload;
		next();
	} catch (e) {
		return res.status(401).json({ error: 'Invalid token' });
	}
}

function decryptPassword(encrypted) {
	const SECRET_KEY = process.env.SECRET_KEY;
	if (!SECRET_KEY) throw new Error('SECRET_KEY not configured');
	// decode base64
	const decoded = Buffer.from(encrypted, 'base64').toString('utf8');
	if (!decoded.endsWith(SECRET_KEY)) throw new Error('Clave inválida o mensaje alterado');
	return decoded.slice(0, -SECRET_KEY.length);
}

function tryDecrypt(maybeEncrypted) {
	try {
		return decryptPassword(maybeEncrypted);
	} catch (e) {
		return maybeEncrypted; // fallback to plain
	}
}

function adminOnly(req, res, next) {
	if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
	if (!req.user.is_admin) return res.status(403).json({ error: 'Requires admin' });
	next();
}


// Ensure announcements table exists (if DB configured)
async function ensureAnnouncementsTable() {
	if (!pool) return;
	try {
		await pool.query(`
			CREATE TABLE IF NOT EXISTS announcements (
				id SERIAL PRIMARY KEY,
				text TEXT NOT NULL,
				active BOOLEAN DEFAULT false,
				starts_at TIMESTAMP NULL,
				ends_at TIMESTAMP NULL,
				created_at TIMESTAMP DEFAULT now(),
				updated_at TIMESTAMP DEFAULT now()
			)
		`);
	} catch (err) {
		console.error('Error ensuring announcements table:', err.message || err);
	}
}
ensureAnnouncementsTable();

// Helper: apply migrations by reading db_schema.sql and executing the SQL
async function applyMigrations() {
	if (!pool) throw new Error('No DB pool');
	const sqlPath = path.join(process.cwd(), 'db_schema.sql');
	if (!fs.existsSync(sqlPath)) throw new Error('db_schema.sql not found');
	const sql = fs.readFileSync(sqlPath, { encoding: 'utf8' });
	await pool.query(sql);
}

// Helper: seed admin and demo users (idempotent)
async function applySeed() {
	if (!pool) throw new Error('No DB pool');
	const adminEmail = 'admin@duoc.cl';
	const r = await pool.query('SELECT id FROM users WHERE email=$1 LIMIT 1', [adminEmail]);
	if (r.rowCount === 0) {
		const hash = await bcrypt.hash('admin123', BCRYPT_ROUNDS);
		await pool.query('INSERT INTO users(name,email,password_hash,is_admin,created_at) VALUES($1,$2,$3,$4,now())', ['admin', adminEmail, hash, true]);
		console.log('Admin user created by applySeed');
	} else console.log('Admin user already exists');

	const demoEmail = 'user@demo.com';
	const r2 = await pool.query('SELECT id FROM users WHERE email=$1 LIMIT 1', [demoEmail]);
	if (r2.rowCount === 0) {
		const hash2 = await bcrypt.hash('user123', BCRYPT_ROUNDS);
		await pool.query('INSERT INTO users(name,email,password_hash,is_admin,created_at) VALUES($1,$2,$3,$4,now())', ['Demo User', demoEmail, hash2, false]);
		console.log('Demo user created by applySeed');
	} else console.log('Demo user already exists');
}

// Internal endpoint to trigger migrations + seed (protected by INTERNAL_SECRET env var)
app.post('/internal/run_migrations_seed', async (req, res) => {
	const key = req.headers['x-internal-key'];
	const secret = process.env.INTERNAL_SECRET;
	if (!secret || !key || key !== secret) return res.status(403).json({ error: 'Forbidden' });
	try {
		await applyMigrations();
	} catch (e) {
		console.error('applyMigrations failed', e && e.message ? e.message : e);
		return res.status(500).json({ error: 'migrations_failed', details: String(e && e.message ? e.message : e) });
	}
	try {
		await applySeed();
	} catch (e) {
		console.error('applySeed failed', e && e.message ? e.message : e);
		return res.status(500).json({ error: 'seed_failed', details: String(e && e.message ? e.message : e) });
	}
	return res.json({ status: 'ok' });
});

// Public message endpoint: returns active announcement from DB if present
app.get('/api/mensaje', async (req, res) => {
	if (!pool) return res.json({ mensaje: 'Hola desde el backend (DB no configurada)' });
	try {
		const q = `SELECT id, text, active, starts_at, ends_at, created_at, updated_at
			FROM announcements
			WHERE active = true
			AND (starts_at IS NULL OR starts_at <= now())
			AND (ends_at IS NULL OR ends_at >= now())
			ORDER BY updated_at DESC
			LIMIT 1`;
		const r = await pool.query(q);
		if (r.rowCount === 0) return res.json({ mensaje: 'Hola desde el backend', db: true, announcement: null });
		const ann = r.rows[0];
		return res.json({ mensaje: ann.text, db: true, announcement: ann });
	} catch (err) {
		console.error('Error fetching announcement:', err.message || err);
		return res.status(200).json({ mensaje: 'Hola desde el backend', db: true, error: String(err.message || err) });
	}
});

// Health check for orchestration / load balancers
app.get('/health', async (req, res) => {
	try {
		if (!pool) return res.status(200).json({ status: 'ok', db: false });
		const r = await pool.query('SELECT 1 as ok');
		return res.status(200).json({ status: 'ok', db: !!r.rows });
	} catch (err) {
		console.error('Health check failed:', err && err.message ? err.message : err);
		return res.status(500).json({ status: 'error', details: String(err && err.message ? err.message : err) });
	}
});

// Auth: register
app.post('/api/auth/register', async (req, res) => {
	const { name, email, password } = req.body;
	if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
	try {
		const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
		const q = 'INSERT INTO users(name, email, password_hash) VALUES($1,$2,$3) RETURNING id, name, email, is_admin';
		const values = [name || '', email.toLowerCase(), hash];
		const result = await pool.query(q, values);
		const user = result.rows[0];
		res.status(201).json({ user });
	} catch (err) {
		console.error(err);
		if (String(err).includes('unique')) return res.status(400).json({ error: 'Email already exists' });
		res.status(500).json({ error: 'Server error' });
	}
});

// Register route matching professor example: requires auth and accepts encrypted password
app.post('/register', authMiddleware, async (req, res) => {
	try {
		const { username, email, password } = req.body;
		if (!username || !email || !password) return res.status(400).json({ error: 'Faltan campos requeridos' });
		const passwordPlain = decryptPassword(password);
		const hash = await bcrypt.hash(passwordPlain, BCRYPT_ROUNDS);
		const q = 'INSERT INTO users(name, email, password_hash) VALUES($1,$2,$3) RETURNING id, name as username, email';
		const r = await pool.query(q, [username, email.toLowerCase(), hash]);
		const newUser = r.rows[0];
		res.status(201).json({ message: 'Usuario registrado exitosamente', user: newUser });
	} catch (error) {
		console.error('Error register:', error);
		res.status(400).json({ error: 'Error al registrar usuario', details: String(error.message) });
	}
});

// Auth: login
app.post('/api/auth/login', async (req, res) => {
	const { email, password } = req.body;
	if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
	try {
		// allow encrypted or plain password from frontend
		const passwordPlain = tryDecrypt(password);
		const q = 'SELECT id, name, email, password_hash, is_admin FROM users WHERE email = $1 LIMIT 1';
		const r = await pool.query(q, [email.toLowerCase()]);
		if (r.rowCount === 0) return res.status(401).json({ error: 'Invalid credentials' });
		const u = r.rows[0];
		const ok = await bcrypt.compare(passwordPlain, u.password_hash);
		if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
		const payload = { id: u.id, email: u.email, name: u.name, is_admin: u.is_admin };
		const token = jwt.sign(payload, process.env.JWT_SECRET || 'devsecret', { expiresIn: '8h' });
		res.json({ token, user: payload });
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

// Update password endpoint similar to example
app.put('/actualizaContrasena', authMiddleware, async (req, res) => {
	try {
		const { username, password, newPassword } = req.body;
		if (!username || !password || !newPassword) return res.status(400).json({ error: 'Faltan datos obligatorios' });

		const plainPassword = decryptPassword(password);
		const plainNew = decryptPassword(newPassword);

		const userQ = 'SELECT id, name, email, password_hash FROM users WHERE name = $1 LIMIT 1';
		const userR = await pool.query(userQ, [username]);
		if (userR.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
		const user = userR.rows[0];
		const isMatch = await bcrypt.compare(plainPassword, user.password_hash);
		if (!isMatch) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
		const newHash = await bcrypt.hash(plainNew, BCRYPT_ROUNDS);
		await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [newHash, user.id]);
		res.json({ message: 'Contraseña actualizada correctamente', user: { id: user.id, name: user.name, email: user.email } });
	} catch (error) {
		console.error('Error actualizaContrasena:', error);
		res.status(500).json({ error: 'Error interno al actualizar la contraseña', details: String(error.message) });
	}
});

app.get('/api/auth/profile', authMiddleware, async (req, res) => {
	try {
		const q = 'SELECT id, name, email, is_admin FROM users WHERE id = $1 LIMIT 1';
		const r = await pool.query(q, [req.user.id]);
		if (r.rowCount === 0) return res.status(404).json({ error: 'User not found' });
		res.json({ user: r.rows[0] });
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

// Products
app.get('/api/products', async (req, res) => {
	try {
		const r = await pool.query('SELECT id, name, description, price, category, image_url, stock FROM products ORDER BY id');
		res.json(r.rows);
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.get('/api/products/:id', async (req, res) => {
	const id = Number(req.params.id);
	try {
		const r = await pool.query('SELECT id, name, description, price, category, image_url, stock FROM products WHERE id=$1 LIMIT 1', [id]);
		if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
		res.json(r.rows[0]);
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.post('/api/products', authMiddleware, adminOnly, async (req, res) => {
	const { name, description, price, category, image_url, stock } = req.body;
	if (!name || !price) return res.status(400).json({ error: 'Name and price required' });
	try {
		const q = 'INSERT INTO products(name, description, price, category, image_url, stock) VALUES($1,$2,$3,$4,$5,$6) RETURNING id, name, description, price, category, image_url, stock';
		const values = [name, description || '', Number(price), category || '', image_url || '', Number(stock) || 0];
		const r = await pool.query(q, values);
		res.status(201).json(r.rows[0]);
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.put('/api/products/:id', authMiddleware, adminOnly, async (req, res) => {
	const id = Number(req.params.id);
	const fields = req.body;
	const allowed = ['name','description','price','category','image_url','stock'];
	const sets = [];
	const values = [];
	let idx = 1;
	for (const k of allowed) {
		if (k in fields) { sets.push(`${k}=$${idx}`); values.push(fields[k]); idx++; }
	}
	if (sets.length === 0) return res.status(400).json({ error: 'No fields' });
	try {
		const q = `UPDATE products SET ${sets.join(',')} WHERE id=$${idx} RETURNING id, name, description, price, category, image_url, stock`;
		values.push(id);
		const r = await pool.query(q, values);
		if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
		res.json(r.rows[0]);
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.delete('/api/products/:id', authMiddleware, adminOnly, async (req, res) => {
	const id = Number(req.params.id);
	try {
		await pool.query('DELETE FROM products WHERE id=$1', [id]);
		res.json({ message: 'Deleted' });
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

// Contact
app.post('/api/contact', async (req, res) => {
	const { name, email, message } = req.body;
	if (!name || !email || !message) return res.status(400).json({ error: 'All fields required' });
	try {
		const q = 'INSERT INTO contacts(name, email, message) VALUES($1,$2,$3) RETURNING id, name, email, message, created_at';
		const r = await pool.query(q, [name, email, message]);
		res.status(201).json(r.rows[0]);
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

// Admin - users
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
	try {
		const r = await pool.query('SELECT id, name, email, is_admin FROM users ORDER BY id');
		res.json(r.rows);
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

// Announcements management (admin)
app.get('/api/announcements', authMiddleware, adminOnly, async (req, res) => {
	try {
		const r = await pool.query('SELECT id, text, active, starts_at, ends_at, created_at, updated_at FROM announcements ORDER BY updated_at DESC');
		res.json(r.rows);
	} catch (err) {
		console.error('Error listing announcements:', err.message || err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.post('/api/announcements', authMiddleware, adminOnly, async (req, res) => {
	try {
		const { text, active, starts_at, ends_at } = req.body;
		if (!text || String(text).trim().length === 0) return res.status(400).json({ error: 'Text required' });
		const r = await pool.query(
			'INSERT INTO announcements(text, active, starts_at, ends_at) VALUES($1,$2,$3,$4) RETURNING id, text, active, starts_at, ends_at, created_at, updated_at',
			[String(text), !!active, starts_at || null, ends_at || null]
		);
		res.status(201).json(r.rows[0]);
	} catch (err) {
		console.error('Error creating announcement:', err.message || err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.put('/api/announcements/:id', authMiddleware, adminOnly, async (req, res) => {
	try {
		const id = Number(req.params.id);
		const { text, active, starts_at, ends_at } = req.body;
		const sets = [];
		const vals = [];
		let idx = 1;
		if (text !== undefined) { sets.push(`text=$${idx++}`); vals.push(String(text)); }
		if (active !== undefined) { sets.push(`active=$${idx++}`); vals.push(!!active); }
		if (starts_at !== undefined) { sets.push(`starts_at=$${idx++}`); vals.push(starts_at || null); }
		if (ends_at !== undefined) { sets.push(`ends_at=$${idx++}`); vals.push(ends_at || null); }
		if (sets.length === 0) return res.status(400).json({ error: 'No fields' });
		// update updated_at
		sets.push(`updated_at=now()`);
		const q = `UPDATE announcements SET ${sets.join(', ')} WHERE id=$${idx} RETURNING id, text, active, starts_at, ends_at, created_at, updated_at`;
		vals.push(id);
		const r = await pool.query(q, vals);
		if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
		res.json(r.rows[0]);
	} catch (err) {
		console.error('Error updating announcement:', err.message || err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.delete('/api/announcements/:id', authMiddleware, adminOnly, async (req, res) => {
	try {
		const id = Number(req.params.id);
		console.log(`DELETE /api/announcements/${id} requested by user ${req.user && req.user.id}`);
		const r = await pool.query('DELETE FROM announcements WHERE id=$1 RETURNING id', [id]);
		if (r.rowCount === 0) {
			console.log(`Announcement id=${id} not found`);
			return res.status(404).json({ error: 'Not found' });
		}
		console.log(`Announcement id=${id} deleted by user ${req.user && req.user.id}`);
		res.json({ message: 'Deleted' });
	} catch (err) {
		console.error('Error deleting announcement:', err.message || err);
		res.status(500).json({ error: 'Server error' });
	}
});

// Orders
app.post('/api/orders', authMiddleware, async (req, res) => {
	const { items } = req.body; // items: [{ product_id, qty }]
	if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'No items' });
	const client = await pool.connect();
	try {
		await client.query('BEGIN');
		// calculate total and validate stock
		let total = 0;
		for (const it of items) {
			const pid = Number(it.product_id);
			const qty = Number(it.qty);
			if (!pid || qty <= 0) throw new Error('Invalid item');
			const r = await client.query('SELECT id, price, stock FROM products WHERE id=$1 LIMIT 1', [pid]);
			if (r.rowCount === 0) throw new Error(`Product ${pid} not found`);
			const p = r.rows[0];
			if (p.stock < qty) throw new Error(`Insufficient stock for product ${pid}`);
			total += Number(p.price) * qty;
		}
		// insert order
		const orderR = await client.query('INSERT INTO orders(user_id, total) VALUES($1,$2) RETURNING id, user_id, total, status, created_at', [req.user.id, total]);
		const order = orderR.rows[0];
		// insert order items and update stock
		for (const it of items) {
			const pid = Number(it.product_id);
			const qty = Number(it.qty);
			const prodR = await client.query('SELECT price FROM products WHERE id=$1 LIMIT 1', [pid]);
			const price = prodR.rows[0].price;
			await client.query('INSERT INTO order_items(order_id, product_id, qty, price) VALUES($1,$2,$3,$4)', [order.id, pid, qty, price]);
			await client.query('UPDATE products SET stock = stock - $1 WHERE id=$2', [qty, pid]);
		}
		await client.query('COMMIT');
		res.status(201).json({ order });
	} catch (err) {
		await client.query('ROLLBACK');
		console.error('Error creating order:', err.message || err);
		res.status(400).json({ error: String(err.message || err) });
	} finally {
		client.release();
	}
});

app.get('/api/orders', authMiddleware, async (req, res) => {
	try {
		let q;
		let vals = [];
		if (req.user.is_admin) {
			q = `SELECT o.id, o.user_id, o.total, o.status, o.created_at,
			COALESCE(json_agg(json_build_object('id', oi.id, 'product_id', oi.product_id, 'qty', oi.qty, 'price', oi.price)) FILTER (WHERE oi.id IS NOT NULL), '[]') AS items
			FROM orders o
			LEFT JOIN order_items oi ON oi.order_id = o.id
			GROUP BY o.id ORDER BY o.id`;
		} else {
			q = `SELECT o.id, o.user_id, o.total, o.status, o.created_at,
			COALESCE(json_agg(json_build_object('id', oi.id, 'product_id', oi.product_id, 'qty', oi.qty, 'price', oi.price)) FILTER (WHERE oi.id IS NOT NULL), '[]') AS items
			FROM orders o
			LEFT JOIN order_items oi ON oi.order_id = o.id
			WHERE o.user_id=$1
			GROUP BY o.id ORDER BY o.id`;
			vals = [req.user.id];
		}
		const r = await pool.query(q, vals);
		res.json(r.rows);
	} catch (err) {
		console.error('Error listing orders:', err.message || err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.get('/api/orders/:id', authMiddleware, async (req, res) => {
	const id = Number(req.params.id);
	try {
		const q = `SELECT o.id, o.user_id, o.total, o.status, o.created_at,
		COALESCE(json_agg(json_build_object('id', oi.id, 'product_id', oi.product_id, 'qty', oi.qty, 'price', oi.price)) FILTER (WHERE oi.id IS NOT NULL), '[]') AS items
		FROM orders o
		LEFT JOIN order_items oi ON oi.order_id = o.id
		WHERE o.id=$1
		GROUP BY o.id LIMIT 1`;
		const r = await pool.query(q, [id]);
		if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
		const order = r.rows[0];
		if (!req.user.is_admin && order.user_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });
		res.json(order);
	} catch (err) {
		console.error('Error getting order:', err.message || err);
		res.status(500).json({ error: 'Server error' });
	}
});

// duplicate routes without /api prefix to match professor examples
app.get('/users', authMiddleware, adminOnly, async (req, res) => {
	try {
		const r = await pool.query('SELECT id, name AS username, email, is_admin FROM users ORDER BY id');
		res.json(r.rows);
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.get('/usersSinSeguridad', async (req, res) => {
	try {
		const r = await pool.query('SELECT id, name AS username, email FROM users ORDER BY id');
		res.json(r.rows);
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

app.put('/api/users/:id/role', authMiddleware, adminOnly, async (req, res) => {
	const uid = Number(req.params.id);
	const { is_admin } = req.body;
	try {
		const r = await pool.query('UPDATE users SET is_admin=$1 WHERE id=$2 RETURNING id, is_admin', [is_admin === true, uid]);
		if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
		res.json(r.rows[0]);
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Server error' });
	}
});

// Serve static frontend build if present (only when build exists)
const staticPath = path.join(__dirname, '..', '..', 'frontend_build');
const indexHtml = path.join(staticPath, 'index.html');
if (fs.existsSync(indexHtml)) {
	app.use(express.static(staticPath));
	app.get(/.*/, (req, res) => {
		res.sendFile(indexHtml);
	});
} else {
	console.log(`Frontend build not found at ${indexHtml} — serving API only.`);
	app.get('/', (req, res) => res.json({ message: 'API running. Frontend build not found.' }));
}

if (process.env.NODE_ENV !== 'test') {
	app.listen(PORT, () => {
		console.log(`Servidor corriendo en http://localhost:${PORT}`);
	});
}

export default app;
