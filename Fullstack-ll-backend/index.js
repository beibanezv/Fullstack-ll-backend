import express from "express";
import cors from "cors";
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
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

app.get('/api/mensaje', (req, res) => res.json({ mensaje: 'Hola desde el backend' }));

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

// Serve static frontend build if present
const staticPath = path.join(__dirname, '..', '..', 'frontend_build');
app.use(express.static(staticPath));
app.get(/.*/, (req, res) => {
	res.sendFile(path.join(staticPath, 'index.html'));
});

app.listen(PORT, () => {
	console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
