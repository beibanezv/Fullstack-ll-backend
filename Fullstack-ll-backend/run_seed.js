import dotenv from 'dotenv';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';

dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL not set in .env');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function run() {
  try {
    // Admin user
    const adminEmail = 'admin@duoc.cl';
    const r = await pool.query('SELECT id FROM users WHERE email=$1 LIMIT 1', [adminEmail]);
    if (r.rowCount === 0) {
      const hash = await bcrypt.hash('admin123', 10);
      await pool.query('INSERT INTO users(name,email,password_hash,is_admin,created_at) VALUES($1,$2,$3,$4,now())', ['admin', adminEmail, hash, true]);
      console.log('Admin user created: admin@duoc.cl / admin123');
    } else {
      console.log('Admin user already exists');
    }

    // Demo regular user
    const demoEmail = 'user@demo.com';
    const r2 = await pool.query('SELECT id FROM users WHERE email=$1 LIMIT 1', [demoEmail]);
    if (r2.rowCount === 0) {
      const hash2 = await bcrypt.hash('user123', 10);
      await pool.query('INSERT INTO users(name,email,password_hash,is_admin,created_at) VALUES($1,$2,$3,$4,now())', ['Demo User', demoEmail, hash2, false]);
      console.log('Demo user created: user@demo.com / user123');
    } else {
      console.log('Demo user already exists');
    }

    await pool.end();
    process.exit(0);
  } catch (err) {
    console.error('Seed error:', err.message || err);
    try { await pool.end(); } catch (e) {}
    process.exit(1);
  }
}

run();
