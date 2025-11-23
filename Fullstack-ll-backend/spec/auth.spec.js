import request from 'supertest';
import app from '../index.js';

describe('Auth endpoints', () => {
  it('POST /api/auth/login with seed admin returns token and user', async () => {
    const payload = { email: 'admin@duoc.cl', password: 'admin123' };
    const res = await request(app).post('/api/auth/login').send(payload);
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    expect(res.body.user).toBeTruthy();
    expect(res.body.user.email).toBe('admin@duoc.cl');
  });
});
