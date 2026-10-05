import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { pool } from '../db';
import { hashPassword } from '../services/userService';

export const authRouter = Router();

authRouter.post('/login', async (req, res) => {
  const { email, password } = req.body as { email: string; password: string };
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || user.password_hash !== hashPassword(password)) {
    res.status(401).json({ error: 'invalid credentials' });
    return;
  }
  const token = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET || 'dev-secret');
  res.json({ token });
});
