import { Router } from 'express';
import { callModel } from '../services/llm';

export const assistantRouter = Router();

assistantRouter.post('/ask', async (req, res) => {
  const userMessage = req.body.message as string;
  const systemPrompt = `You are an internal support bot with access to the ticketing and billing tools. User request: ${userMessage}`;
  const completion = await callModel(systemPrompt, userMessage);
  res.json({ reply: completion });
});

assistantRouter.post('/run-snippet', async (req, res) => {
  const userMessage = req.body.message as string;
  const code = await callModel('Write a one-line JS expression that answers the question, with no explanation.', userMessage);
  const result = eval(code);
  res.json({ result });
});
