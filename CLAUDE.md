# HQ OIDC – minimal Joomla OIDC SSO plugin

**Purpose:** Joomla 5/6 system plugin (`plg_system_hqoidc`) that logs users in via OpenID Connect (auth code + PKCE, match-only or auto-create users, RP-initiated logout). Built for malarscouterna.se against Scouterna's Keycloak. Public repo: `github.com/magnushasselquist/joomla-hq-oidc` (the folder name still says "easy-oidc", the plugin was renamed to HQ OIDC in v1.0.1). Currently v1.0.2 in production.

**Stack:** PHP >= 8.1, Composer (`composer.phar` bundled at repo root), `firebase/php-jwt` as the only runtime dependency. Namespaced plugin: `plg_system_hqoidc/src/Extension/HqOidc.php` (Joomla glue: routing, session, user matching, login/logout events) + `src/Oidc/` (`Discovery`, `Client`, `TokenVerifier`, `HttpClientInterface`/`JoomlaHttpClient` — the OIDC protocol code) + `services/provider.php` + manifest `hqoidc.xml`; en-GB and sv-SE language files.

## Build / test / release
- `./build.sh` → regenerates `vendor/` (no-dev) and zips `dist/plg_system_hqoidc-<version>.zip` (excludes `tests/`).
- Unit tests: `cd plg_system_hqoidc && php ../composer.phar install && vendor/bin/phpunit` (`failOnDeprecation` is on; discovery fixtures in `tests/fixtures/`). After `build.sh`, run `composer install` again to get PHPUnit back.
- Manual test = install the zip on a Joomla site and log in.
- Release steps are in `README.md` ("Releasing a new version"): bump `<version>` in `hqoidc.xml` **and** `docs/updates.xml` (version + downloadurl tag `vX.Y.Z`), build, commit, `gh release create vX.Y.Z dist/...zip`. GitHub Pages serves `docs/updates.xml` as the Joomla update server.

## Rules / gotchas
- `vendor/`, `composer.lock`, `dist/`, `composer.phar` are gitignored — never commit them.
- `PLAN.md` is an untracked internal business/roadmap document; the file itself says not to commit it to the public repo.
- The plugin element name `hqoidc` and the update-server URL are baked into every installation; changing either breaks existing installs (see PLAN.md, Fas 0).
- Manifest default `issuer_url` points at `dev.id.scouterna.se` — PLAN.md wants that default removed before JED publication.
- No secrets in the repo; client secret is entered in Joomla plugin params.
- `src/Oidc/` must not use Joomla classes (only `JoomlaHttpClient` may) — the tests run without Joomla.
- Redirects go through `$app->redirect()`, never raw `header()` + `exit`: Joomla persists the session in a shutdown function, and a raw exit after `session_write_close()` loses the pending state/nonce.
- Do not commit from Claude unless asked.
