-- SQL schema for Neon (Postgres)

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_admin BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  price INTEGER NOT NULL,
  category TEXT,
  image_url TEXT,
  stock INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS contacts (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  total INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS order_items (
  id SERIAL PRIMARY KEY,
  order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
  product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
  qty INTEGER NOT NULL,
  price INTEGER NOT NULL
);

-- Announcements table
CREATE TABLE IF NOT EXISTS announcements (
  id SERIAL PRIMARY KEY,
  text TEXT NOT NULL,
  active BOOLEAN DEFAULT false,
  starts_at TIMESTAMP NULL,
  ends_at TIMESTAMP NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Seed sample products (no duplicate if re-run)
INSERT INTO products(name, description, price, category, image_url, stock)
SELECT 'Perfume Floral', 'Aroma floral y fresco', 25990, 'Femenino', '', 10
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = 'Perfume Floral');

INSERT INTO products(name, description, price, category, image_url, stock)
SELECT 'Colonia Ambar', 'Notas ambarinas y duraderas', 19990, 'Masculino', '', 8
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = 'Colonia Ambar');

-- Seed sample announcements (no duplicate if re-run)
INSERT INTO announcements(text, active, starts_at, ends_at)
SELECT 'Bienvenidos a PerfumeStore — 10% en tu primera compra', true, now(), null
WHERE NOT EXISTS (SELECT 1 FROM announcements WHERE text LIKE 'Bienvenidos a PerfumeStore%');

INSERT INTO announcements(text, active) 
SELECT 'Oferta puntual: envío gratis hoy', false
WHERE NOT EXISTS (SELECT 1 FROM announcements WHERE text = 'Oferta puntual: envío gratis hoy');
