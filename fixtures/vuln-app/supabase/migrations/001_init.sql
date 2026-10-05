create table users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password_hash text not null,
  role text not null default 'user'
);

create table invoices (
  id uuid primary key default gen_random_uuid(),
  customer_name text not null,
  owner_id uuid references users(id),
  amount_cents integer not null,
  created_at timestamptz not null default now()
);

alter table invoices disable row level security;
