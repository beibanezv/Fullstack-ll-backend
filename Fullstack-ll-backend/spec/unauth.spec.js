import request from 'supertest';
import app from '../index.js';

describe('Public endpoints', () => {
  it('GET /api/mensaje returns JSON with mensaje', async () => {
    const res = await request(app).get('/api/mensaje');
    expect(res.status).toBe(200);
    expect(res.body).toBeTruthy();
    // may contain mensaje string or announcement
    expect(res.body.mensaje !== undefined || res.body.announcement !== undefined).toBeTrue();
  });

  it('GET /api/products returns array', async () => {
    const res = await request(app).get('/api/products');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBeTrue();
  });
});
