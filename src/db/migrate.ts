import { pool } from "./db.js";

async function main() {
  // Idempotent "MVP migrations". If you want strict migrations later, switch to a real migrator.
  await pool.query(`
    create table if not exists users (
      id uuid primary key,
      email text not null unique,
      password_hash text not null,
      created_at timestamptz not null default now()
    );
  `);

  await pool.query(`
    create table if not exists instances (
      id uuid primary key,
      user_id uuid not null references users(id) on delete cascade,
      slug text not null unique,
      status text not null,
      container_name text not null,
      state_volume text not null,
      owner_e164 text null,
      default_model text null,
      power_user_enabled boolean not null default false,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      last_health_at timestamptz null,
      last_whatsapp_connected_at timestamptz null
    );
  `);

  await pool.query(`
    create table if not exists instance_secrets (
      id uuid primary key,
      instance_id uuid not null references instances(id) on delete cascade,
      key text not null,
      ciphertext text not null,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      unique(instance_id, key)
    );
  `);

  await pool.query(`
    create table if not exists instance_members (
      instance_id uuid not null references instances(id) on delete cascade,
      user_id uuid not null references users(id) on delete cascade,
      role text not null,
      created_at timestamptz not null default now(),
      primary key(instance_id, user_id)
    );
  `);

  await pool.query(`
    create table if not exists audit_log (
      id uuid primary key,
      user_id uuid null references users(id) on delete set null,
      instance_id uuid null references instances(id) on delete set null,
      action text not null,
      meta jsonb not null default '{}'::jsonb,
      created_at timestamptz not null default now()
    );
  `);

  console.log("db:init ok");
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await pool.end();
  });

