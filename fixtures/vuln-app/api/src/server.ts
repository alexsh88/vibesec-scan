import express from 'express';
import cors from 'cors';
import { invoicesRouter } from './routes/invoices';
import { adminRouter } from './routes/admin';
import { mediaRouter } from './routes/media';
import { filesRouter } from './routes/files';
import { logsRouter } from './routes/logs';
import { fetchRouter } from './routes/fetchUrl';
import { redirectRouter } from './routes/redirect';
import { assistantRouter } from './routes/assistant';
import { authRouter } from './routes/auth';

const app = express();
app.use(express.json());

app.use(cors({ origin: '*', credentials: true }));

app.use('/api/invoices', invoicesRouter);
app.use('/api/admin', adminRouter);
app.use('/api/media', mediaRouter);
app.use('/api/files', filesRouter);
app.use('/api/logs', logsRouter);
app.use('/api/fetch', fetchRouter);
app.use('/api/redirect', redirectRouter);
app.use('/api/assistant', assistantRouter);
app.use('/api/auth', authRouter);

app.listen(Number(process.env.PORT) || 3000);
