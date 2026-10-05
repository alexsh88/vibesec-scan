import crypto from 'node:crypto';
import { pool } from '../db';

export function hashPassword(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex');
}

export async function createUser(email: string, password: string) {
  const hashed = hashPassword(password);
  return pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, hashed]);
}
