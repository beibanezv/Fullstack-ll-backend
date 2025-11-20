import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import { Pool } from 'pg';

dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL not set in .env');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function run() {
  try {
    const sqlPath = path.join(process.cwd(), 'db_schema.sql');
    const sql = fs.readFileSync(sqlPath, { encoding: 'utf8' });
    console.log('Running migrations from', sqlPath);
    await pool.query(sql);
    console.log('Migrations applied successfully');
    await pool.end();
    process.exit(0);
  } catch (err) {
    console.error('Migration error:', err.message || err);
    await pool.end();
    process.exit(1);
  }
}

run();
