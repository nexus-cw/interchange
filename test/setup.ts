// Applies the initial schema to the ephemeral per-test D1 instance.
// Imported by each test file that needs a populated DB.
//
// Can't use node:fs in the Workers runtime, so the migration is imported as
// a raw string via Vite's ?raw loader (vitest-pool-workers uses Vite).

import { env } from "cloudflare:test";
// @ts-expect-error — ?raw is a Vite loader suffix without TS types.
import MIGRATION from "../migrations/0001_init.sql?raw";

let applied = false;

export async function applyMigrations(): Promise<void> {
  if (applied) return;
  const statements = (MIGRATION as string)
    .split(/;\s*$/m)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !s.startsWith("--"));
  const db = (env as { DB: D1Database }).DB;
  for (const stmt of statements) {
    await db.prepare(stmt).run();
  }
  applied = true;
}
