import request from 'supertest';
import app from '../index.js';

describe('Additional simple tests', () => {
  it('POST /api/contact without required fields returns 400', async () => {
    const res = await request(app).post('/api/contact').send({ name: 'x' });
    expect(res.status).toBe(400);
  });

  it('POST /api/contact with valid data returns 201', async () => {
    const payload = { name: 'Test', email: 'test@example.com', message: 'Hola' };
    const res = await request(app).post('/api/contact').send(payload);
    expect([201,200]).toContain(res.status);
    expect(res.body).toBeTruthy();
  });

  it('GET /api/products/:id returns a product when id exists', async () => {
    const list = await request(app).get('/api/products');
    expect(list.status).toBe(200);
    const arr = list.body;
    if (!Array.isArray(arr) || arr.length === 0) {
      // If no products, assert array and skip detailed check
      expect(Array.isArray(arr)).toBeTrue();
      return;
    }
    const id = arr[0].id;
    const res = await request(app).get(`/api/products/${id}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(id);
  });

  it('GET /api/announcements without token returns 401', async () => {
    const res = await request(app).get('/api/announcements');
    expect(res.status).toBe(401);
  });

  it('GET /api/announcements with admin token returns array', async () => {
    const login = await request(app).post('/api/auth/login').send({ email: 'admin@duoc.cl', password: 'admin123' });
    expect(login.status).toBe(200);
    const token = login.body.token;
    const res = await request(app).get('/api/announcements').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBeTrue();
  });

  it('GET /api/auth/profile with token returns user', async () => {
    const login = await request(app).post('/api/auth/login').send({ email: 'admin@duoc.cl', password: 'admin123' });
    expect(login.status).toBe(200);
    const token = login.body.token;
    const res = await request(app).get('/api/auth/profile').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.user).toBeTruthy();
    expect(res.body.user.email).toBe('admin@duoc.cl');
  });

});
