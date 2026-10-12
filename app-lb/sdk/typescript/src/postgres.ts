/**
 * One namespace's Postgres databases, through app-lb's `postgres` plugin.
 * Mirrors the `hws` crate's `PostgresClient`.
 *
 * The operator switches the plugin on for the fleet, pointing it at the
 * region's pg-fc pool; a namespace administrator installs it. Each database
 * gets its own role and password, and by default its credentials are also
 * written to the namespace secret `pg-<name>` (`url`, `host`, `port`,
 * `database`, `user`, `password`), where a deployment's `env_from` reads them.
 *
 * ```ts
 * await lb.installPlugin("team-a", "postgres");
 * const pg = lb.postgres("team-a");
 * const db = await pg.createDatabase({ name: "app" });
 * // db.password / db.url are returned this once; they are also in `pg-app`.
 * const { databases } = await pg.databases();
 * await pg.deleteDatabase("app");
 * ```
 *
 * Every method rejects with a `ConflictError` whose `code` is
 * `plugin_not_installed` or `plugin_disabled` when the plugin is not usable in
 * the namespace.
 */

import type { Heyctl } from "./client.js";
import type {
  CreatedPostgresDatabase,
  DeletedPostgresDatabase,
  PostgresDatabases,
} from "./types.js";

/** The plugin id of the Postgres plugin. */
export const POSTGRES_PLUGIN = "postgres";

/** The body of {@link PostgresClient.createDatabase}. */
export interface NewDatabase {
  /** 1–31 lowercase letters, digits or `_`, starting with a letter. */
  name: string;
  /** Also write the credentials to the namespace secret `pg-<name>`. Default `true`. */
  secret?: boolean;
}

const seg = encodeURIComponent;

export class PostgresClient {
  constructor(
    private readonly client: Heyctl,
    readonly namespace: string,
  ) {}

  private path(rest: string): string {
    return `/namespaces/${seg(this.namespace)}/plugins/${POSTGRES_PLUGIN}/api/${rest}`;
  }

  /** The namespace's databases, and where they are reached. Never carries a password. */
  databases(signal?: AbortSignal): Promise<PostgresDatabases> {
    return this.client.request("GET", this.path("databases"), {
      kind: "namespace",
      name: this.namespace,
      signal,
    });
  }

  /**
   * Create a database with its own role and password. Needs `admin` in the
   * namespace. The password comes back this once. A name already in use, an
   * existing `pg-<name>` secret, or a namespace at the host's limit is a
   * `ConflictError`.
   */
  createDatabase(db: NewDatabase, signal?: AbortSignal): Promise<CreatedPostgresDatabase> {
    return this.client.request("POST", this.path("databases"), {
      body: { name: db.name, secret: db.secret ?? true },
      kind: "database",
      name: db.name,
      signal,
    });
  }

  /**
   * Revoke a database's credential and forget it. Needs `admin` in the
   * namespace. Its data stays on pg-fc until an operator purges it, and its
   * `pg-<name>` secret is left in place.
   */
  deleteDatabase(name: string, signal?: AbortSignal): Promise<DeletedPostgresDatabase> {
    return this.client.request("DELETE", this.path(`databases/${seg(name)}`), {
      kind: "database",
      name,
      signal,
    });
  }
}
