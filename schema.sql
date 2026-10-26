create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  email text not null unique,
  phone text,
  password_hash text,
  google_id text unique,
  email_verified boolean not null default false,
  verify_hash text,
  verify_expires timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists users_verify_hash_idx on users (verify_hash);
