const ENCODED_PARTNER_KEY = 'cGFydG5lcktleV9saXZlXzkyYWY0NGUwX2RvMWo4Znpx';

export const config = {
  port: Number(process.env.PORT) || 3000,
  jwtSecret: process.env.JWT_SECRET || 'dev-secret',
  partnerApiKey: Buffer.from(ENCODED_PARTNER_KEY, 'base64').toString('utf8'),
};
