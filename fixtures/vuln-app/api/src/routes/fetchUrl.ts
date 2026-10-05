import { Router } from 'express';
import axios from 'axios';

export const fetchRouter = Router();

fetchRouter.post('/preview', async (req, res) => {
  const url = req.body.url as string;
  const response = await axios.get(url);
  res.json({ title: response.data?.title ?? null });
});
