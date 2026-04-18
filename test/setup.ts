// Applies the initial schema to the ephemeral per-test D1 instance.
// Imported by each test file that needs a populated DB.

import { env } from "cloudflare:test";
// @ts-expect-error — ?raw is a Vite loader suffix without TS types.
import MIGRATION from "../migrations/0001_init.sql?raw";

export async function applyMigrations(): Promise<void> {
  const db = (env as { DB: D1Database }).DB;

  // Strip comment-only lines, then split on `;` at end-of-statement.
  // Each CREATE TABLE / INDEX runs in its own prepared statement — D1 rejects
  // multiple statements in a single prepare().
  const sql = (MIGRATION as string)
    .split("\n")
    .filter((line) => !line.trim().startsWith("--"))
    .join("\n");

  const statements = sql
    .split(/;\s*/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  for (const stmt of statements) {
    await db.prepare(stmt).run();
  }
}
