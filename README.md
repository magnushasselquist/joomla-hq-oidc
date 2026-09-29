# HQ OIDC — minimal Joomla SSO plugin

A small Joomla system plugin that authenticates users against an OpenID Connect
identity provider (designed for Keycloak, but standards-compliant so it works
with anything that publishes `.well-known/openid-configuration`).

Originally built for [mälarscouterna.se](https://malarscouterna.se) as a cheap,
low-maintenance alternative to the miniOrange "Joomla SSO OAuth OIDC" plugin.
Designed to run on **Joomla 5** today and stay compatible with **Joomla 6**
(namespaced plugin, event-subscriber pattern, no deprecated APIs).

## What it does

- OIDC authorization-code flow with **PKCE**.
- Verifies the ID token itself: signature against the provider's JWKS,
  issuer, audience/`azp`, nonce and expiry. The only runtime dependency is
  `firebase/php-jwt`.
- Also reads the userinfo endpoint, so providers that keep profile claims out
  of the ID token (Okta, some Keycloak mappers) still work.
- Matches the IdP user to a Joomla user by **username** (claim
  `preferred_username`) or **email** — configurable. Defaults to username.
- Two provisioning modes — **match-only** (reject unknown users, the safe
  default) or **auto-create** (provision new Joomla users from claims).
- **RP-initiated single logout** — logging out of Joomla also signs the user out
  of the IdP.
- All configuration via standard Joomla plugin parameters.

## What it deliberately does *not* do

- No login button module. You build your own button as a plain HTML link
  pointing at `/index.php?option=hqoidc&task=login`.
- No group/role mapping from Keycloak claims (yet). Auto-created users get the
  configured default group.
- No multi-IdP support. One plugin, one IdP.
- No back-channel logout, no token refresh, no introspection. The plugin is for
  authentication only; we don't keep an OIDC session after login.
- No PS256- or EdDSA-signed ID tokens. RS256/384/512 and ES256/384 are
  supported; leave the client at RS256, the OIDC default.
- No Apple Sign In (JWT-signed client secret, `form_post`, name only on first
  login — it is not generic OIDC).

## Installing

1. Download the latest release `plg_system_hqoidc-x.y.z.zip` from
   [GitHub Releases](https://github.com/magnushasselquist/joomla-hq-oidc/releases)
   (or run `./build.sh` from the repo).
2. In Joomla admin → **System → Install → Extensions** → upload the zip.
3. Enable **System - HQ OIDC** under **System → Plugins**.

Once installed, Joomla's built-in extension updater will pick up new releases
automatically (the plugin manifest declares an update server).

## Configuring

In Joomla admin → **System → Plugins → System - HQ OIDC**:

| Setting | What to put |
| --- | --- |
| Issuer URL | e.g. `https://dev.id.scouterna.se/realms/scouterna` |
| Client ID | From your Keycloak client |
| Client Secret | From your Keycloak client (confidential clients only) |
| Match field | `Username` (matches `preferred_username`) or `Email` |
| Provisioning | `Match only` (reject unknown) or `Auto-create` |
| Single Logout | Yes (recommended) |

**Keycloak client setup:**

- *Client authentication*: On (confidential) or Off (public + PKCE).
- *Valid redirect URIs*: `https://your-joomla-site.example/index.php?option=hqoidc&task=callback`
- *Valid post-logout redirect URIs*: `https://your-joomla-site.example/` (or whatever you
  set in "Post-logout URL")
- Scopes: `openid`, `profile`, `email`.

**Other providers:** anything that publishes `.well-known/openid-configuration`
should work. Microsoft Entra ID needs the tenant-specific issuer
(`https://login.microsoftonline.com/<tenant-id>/v2.0`), not `/common`.

## Usage — building your login button

Anywhere in your Joomla content, module, or template, add a link:

```html
<a class="btn btn-primary" href="/index.php?option=hqoidc&task=login">
    Sign in with Scouterna ID
</a>
```

Optionally pass a `return` query parameter to redirect the user back to a
specific page after login:

```html
<a href="/index.php?option=hqoidc&task=login&return=/medlemmar">
    Sign in
</a>
```

Logout link:

```html
<a href="/index.php?option=hqoidc&task=logout">Sign out</a>
```

This triggers RP-initiated single logout when enabled; otherwise just a normal
Joomla logout.

## URLs the plugin handles

| URL | Purpose |
| --- | --- |
| `/index.php?option=hqoidc&task=login` | Start auth code + PKCE flow, redirect to IdP. Honors `?return=<safe-relative-url>`. |
| `/index.php?option=hqoidc&task=callback` | OIDC redirect URI. Validates the ID token, matches/creates user, signs them into Joomla. |
| `/index.php?option=hqoidc&task=logout` | Joomla logout, then RP-initiated logout at the IdP if enabled. |

## Building the package zip

Requirements: PHP 8.1+, `php composer.phar` (one comes bundled at the repo root).

```sh
./build.sh
# → ./dist/plg_system_hqoidc-<version>.zip
```

The script reads the version from `plg_system_hqoidc/hqoidc.xml`,
regenerates `vendor/` with `--no-dev --optimize-autoloader`, and zips up the
installable plugin (stripping `tests/`, vendor `docs/`, dotfiles, etc.).

## Running the tests

```sh
cd plg_system_hqoidc
php ../composer.phar install
vendor/bin/phpunit
```

The suite covers discovery parsing (against documents captured from Keycloak,
Google and Entra ID in `tests/fixtures/`), the token-endpoint client, and ID
token verification with generated RSA and EC keys. `build.sh` reinstalls
`vendor/` without dev dependencies, so run `composer install` again afterwards
to get PHPUnit back.

## Releasing a new version

The release process is fully manual — no CI yet. To cut version `x.y.z`:

1. Bump `<version>x.y.z</version>` in `plg_system_hqoidc/hqoidc.xml`.
2. In `docs/updates.xml`, bump both `<version>` and the `<downloadurl>` (the
   `v<x.y.z>` segment and the `-x.y.z.zip` filename must match the new tag).
3. `./build.sh` → produces `dist/plg_system_hqoidc-x.y.z.zip` and prints its
   checksums.
4. Paste the printed `<sha256>` and `<sha512>` into `docs/updates.xml`. Joomla
   verifies the downloaded zip against them and warns the admin when they are
   missing.
5. Commit and push:
   ```sh
   git add plg_system_hqoidc/hqoidc.xml docs/updates.xml
   git commit -m "Release vx.y.z"
   git push
   ```
6. Create the GitHub release with the zip attached:
   ```sh
   gh release create vx.y.z dist/plg_system_hqoidc-x.y.z.zip \
       --title "vx.y.z" --notes "Release notes here"
   ```

Once the release is published, GitHub Pages serves the updated
`updates.xml` at <https://magnushasselquist.github.io/joomla-hq-oidc/updates.xml>
(usually within a minute). Existing Joomla installations running the previous
version will pick up the new release through Joomla's built-in extension
updater.

### Things that are easy to forget

- The `<downloadurl>` in `updates.xml` and the GitHub release tag must agree on
  the exact `vx.y.z` form (with the `v` prefix).
- The checksums in `updates.xml` must match the zip attached to the release
  byte for byte. Rebuilding produces a different zip, so attach the exact file
  you hashed.
- `<element>hqoidc</element>` and `<folder>system</folder>` in `updates.xml`
  must keep matching the plugin name in `hqoidc.xml` — Joomla uses these to
  pair an installed plugin to its update feed.
- `vendor/`, `composer.lock`, and `dist/` are gitignored. Don't commit them by
  accident.

## Troubleshooting

- Enable **Debug log** in plugin params; entries go to `hqoidc.log` in the
  directory Joomla's `log_path` config points at (Global Configuration →
  System → Path to Log Folder). Typically that's `administrator/logs/`, but
  some installs override it.
- "No matching Joomla account was found" — provisioning is `match_only` and no
  Joomla user matches the IdP claim. Either create the Joomla user with the
  matching username/email, or flip provisioning to `auto-create`.
- "No pending authorization in the session" in the log means the Joomla
  session was lost between `task=login` and `task=callback`. Check that
  cookies are not being blocked and that the site is served over HTTPS in
  production.
- "ID token is signed with PS256 …" — switch the IdP client's ID token
  signature algorithm to RS256.
- "Discovery issuer … does not match" — the Issuer URL must be exactly what
  the provider publishes as `issuer`; for Entra ID that is the tenant-specific
  URL, never `/common`.

## Forward compatibility

Joomla 6 requires the namespaced plugin pattern; we already use it. Manifest
declares `<minimumPhp>8.1</minimumPhp>` and only uses public, non-deprecated
APIs (`CMSApplicationInterface`, `Joomla\Event\SubscriberInterface`,
`Joomla\Database\DatabaseInterface`, `Joomla\CMS\User\UserHelper`,
`Joomla\CMS\User\User`).

## License

GPL-2.0-or-later (matching Joomla's license).
