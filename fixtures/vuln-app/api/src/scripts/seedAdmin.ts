import { pool } from '../db';
import { hashPassword } from '../services/userService';

const credentials = { email: 'admin@example.com', password: 'Tr0ub4dor&3xyzQ9' };

export async function seedAdmin(): Promise<void> {
  await pool.query('INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)', [
    credentials.email,
    hashPassword(credentials.password),
    'admin',
  ]);
}
