/**
 * Adds the Amazon RDS certificate authorities to Node's default TLS trust store when the
 * server starts, so the Postgres connection can verify the RDS server certificate
 * (`sslmode=verify-full`) in Netlify functions.
 *
 * Fork-specific file, not part of upstream umami.
 *
 * Why this is needed
 * ------------------
 * Our database is on Amazon RDS, which only accepts SSL connections. RDS server
 * certificates are signed by Amazon's own RDS certificate authorities, which are not in
 * Node's built-in list of trusted CAs. Without them, `pg` (used by Prisma through
 * `@prisma/adapter-pg`) rejects the connection with
 * `self-signed certificate in certificate chain`.
 *
 * Why not `NODE_EXTRA_CA_CERTS`
 * -----------------------------
 * The usual fix is to set `NODE_EXTRA_CA_CERTS` to the path of the RDS CA bundle. That
 * works for the Netlify build, where `scripts/check-db.js` runs from the repo root and
 * the variable points at `certs/global-bundle.pem`. It does not work in the deployed
 * Netlify functions: Node only reads `NODE_EXTRA_CA_CERTS` once, at process startup,
 * and there it had no effect. No path we tried (relative or absolute) loaded the CAs,
 * and Node did not even print its usual "Ignoring extra certs" warning. That suggests
 * the variable is not present when the function process starts, most likely because
 * Netlify adds environment variables after Node has booted.
 *
 * Why not `sslmode=no-verify`
 * ---------------------------
 * `no-verify` keeps the connection encrypted but skips checking the server certificate,
 * so it does not prove we are talking to our RDS instance and leaves the connection open
 * to impersonation (man-in-the-middle). We want full verification.
 *
 * Why this file and not a change to umami's code
 * ----------------------------------------------
 * Passing a `ca` option to the Postgres driver would mean editing `src/lib/prisma.ts` and
 * `scripts/check-db.js`, which would conflict with upstream umami updates. Next.js calls
 * `register()` in `src/instrumentation.ts` once when the server starts, before it handles
 * any request, and upstream umami does not have this file. Adding it lets us change the
 * process-wide default trust store without touching any upstream file.
 *
 * How it works
 * ------------
 * `tls.setDefaultCACertificates()` (Node >= 22.19 / >= 24.5) replaces the default CA list
 * used by TLS clients that don't pass their own `ca` option, which includes `pg`. We pass
 * the current defaults (Node's built-in CAs, plus anything from `NODE_EXTRA_CA_CERTS`)
 * plus the RDS CAs, so trust is only extended, never narrowed. The bundle is inlined in
 * `src/rds-ca-bundle.ts` so it is compiled into the function and needs no file path at
 * runtime.
 *
 * Required configuration
 * ----------------------
 * - `DATABASE_URL` should use `sslmode=verify-full`.
 * - `NODE_EXTRA_CA_CERTS=certs/global-bundle.pem` is still needed for the build, because
 *   `scripts/check-db.js` runs outside Next.js and never runs this file.
 *
 * If upstream umami adds its own `src/instrumentation.ts`, merge this logic into their
 * `register()` function.
 */
export async function register() {
  // Instrumentation also runs in the Edge runtime, which has no `node:tls`.
  if (process.env.NEXT_RUNTIME !== 'nodejs') {
    return;
  }

  const tls = await import('node:tls');
  const { RDS_CA_BUNDLE } = await import('./rds-ca-bundle');

  if (typeof tls.setDefaultCACertificates !== 'function') {
    console.warn(
      `Amazon RDS CAs not added: tls.setDefaultCACertificates() requires Node >= 22.19 or >= 24.5 (running ${process.version}).`,
    );
    return;
  }

  const rdsCerts =
    RDS_CA_BUNDLE.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];

  tls.setDefaultCACertificates([...tls.getCACertificates('default'), ...rdsCerts]);

  console.log(`Added ${rdsCerts.length} Amazon RDS CAs to the default TLS trust store.`);
}
