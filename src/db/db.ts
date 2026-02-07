import pg from "pg";
import { config } from "../config.js";

export const pool = new pg.Pool({
  connectionString: config.databaseUrl,
});

export async function query<T = unknown>(text: string, params: unknown[] = []): Promise<T[]> {
  const res = await pool.query(text, params as any[]);
  return res.rows as T[];
}

