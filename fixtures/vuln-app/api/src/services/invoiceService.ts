import { pool } from '../db';

export async function findInvoicesByCustomer(customerName: string) {
  const sql = "SELECT * FROM invoices WHERE customer_name = '" + customerName + "'";
  return pool.query(sql);
}

export async function getInvoiceById(id: string) {
  const result = await pool.query('SELECT * FROM invoices WHERE id = $1', [id]);
  return result.rows[0];
}
