import { Router } from 'express';
import { findInvoicesByCustomer, getInvoiceById } from '../services/invoiceService';

export const invoicesRouter = Router();

invoicesRouter.get('/search', async (req, res) => {
  const customerName = req.query.customer as string;
  const rows = await findInvoicesByCustomer(customerName);
  res.json(rows);
});

invoicesRouter.get('/:id', async (req, res) => {
  const invoice = await getInvoiceById(req.params.id);
  res.json(invoice);
});
