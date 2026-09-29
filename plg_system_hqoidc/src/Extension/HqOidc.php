<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Extension;

\defined('_JEXEC') or die;

use Firebase\JWT\JWT;
use Joomla\CMS\Application\CMSApplicationInterface;
use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\CMS\User\UserHelper;
use Joomla\Database\DatabaseInterface;
use Joomla\Event\EventInterface;
use Joomla\Event\SubscriberInterface;
use Joomla\Plugin\System\HqOidc\Oidc\Client;
use Joomla\Plugin\System\HqOidc\Oidc\Discovery;
use Joomla\Plugin\System\HqOidc\Oidc\JoomlaHttpClient;
use Joomla\Plugin\System\HqOidc\Oidc\OidcException;
use Joomla\Plugin\System\HqOidc\Oidc\TokenVerifier;

/**
 * HQ OIDC system plugin.
 *
 * Handles OIDC authentication against an external IdP (designed for Keycloak)
 * via three custom URLs:
 *   index.php?option=hqoidc&task=login
 *   index.php?option=hqoidc&task=callback
 *   index.php?option=hqoidc&task=logout
 */
final class HqOidc extends CMSPlugin implements SubscriberInterface
{
    /** Pending authorization (state, nonce, PKCE verifier, return URL) between login and callback. */
    private const SESSION_AUTH = 'hqoidc.auth';

    private const SESSION_ID_TOKEN = 'hqoidc.id_token';

    /** Seconds a pending authorization stays valid. */
    private const AUTH_MAX_AGE = 600;

    protected $autoloadLanguage = true;

    /** ID token captured in onUserLogout, redirected with in onUserAfterLogout. */
    private ?string $pendingLogoutIdToken = null;

    public static function getSubscribedEvents(): array
    {
        return [
            'onAfterRoute'      => 'onAfterRoute',
            'onUserLogout'      => 'onUserLogout',
            'onUserAfterLogout' => 'onUserAfterLogout',
        ];
    }

    public function onAfterRoute($event = null): void
    {
        $app = $this->getApplication();

        if (!$app instanceof CMSApplicationInterface) {
            return;
        }

        if ($app->getInput()->getCmd('option') !== 'hqoidc') {
            return;
        }

        $this->ensureVendorAutoload();

        $task = $app->getInput()->getCmd('task');

        try {
            switch ($task) {
                case 'login':
                    $this->startLogin($app);
                    break;
                case 'callback':
                    $this->handleCallback($app);
                    break;
                case 'logout':
                    $this->handleLogout($app);
                    break;
                default:
                    $app->enqueueMessage(Text::_('PLG_SYSTEM_HQOIDC_ERR_UNKNOWN_TASK'), 'error');
                    $app->redirect(Uri::root());
            }
        } catch (\Throwable $e) {
            $this->log('OIDC failure: ' . $e->getMessage(), Log::ERROR);
            $app->enqueueMessage(Text::_('PLG_SYSTEM_HQOIDC_ERR_SIGN_IN_FAILED'), 'error');
            $app->redirect(Uri::root());
        }
    }

    /**
     * Fires for our task=logout flow and for Joomla's own logout button alike.
     * Runs before plg_user_joomla destroys the session, so this is the last
     * chance to read the ID token; the redirect itself waits for
     * onUserAfterLogout so Joomla completes its own logout first.
     */
    public function onUserLogout($event = null): void
    {
        $app = $this->getApplication();

        if (!$app instanceof CMSApplicationInterface) {
            return;
        }

        if ((int) $this->params->get('single_logout', 1) !== 1) {
            return;
        }

        $idToken = $app->getSession()->get(self::SESSION_ID_TOKEN);

        if (!\is_string($idToken) || $idToken === '') {
            return;
        }

        // An administrator ending another user's session must not be signed
        // out of the IdP themselves.
        $subject   = $event instanceof EventInterface ? $event->getArgument('subject') : null;
        $targetId  = \is_array($subject) ? (int) ($subject['id'] ?? 0) : 0;
        $currentId = (int) ($app->getIdentity()?->id ?? 0);

        if ($targetId !== 0 && $targetId !== $currentId) {
            return;
        }

        $this->pendingLogoutIdToken = $idToken;
    }

    public function onUserAfterLogout($event = null): void
    {
        $idToken                    = $this->pendingLogoutIdToken;
        $this->pendingLogoutIdToken = null;

        if ($idToken === null) {
            return;
        }

        $app = $this->getApplication();

        if (!$app instanceof CMSApplicationInterface) {
            return;
        }

        try {
            [, $client] = $this->connect();

            $url = $client->endSessionUrl(
                $idToken,
                $this->absoluteUrl($this->params->get('post_logout_url', '/') ?: '/')
            );

            if ($url === null) {
                $this->log('Single logout skipped: provider publishes no end_session_endpoint');

                return;
            }

            $app->redirect($url);
        } catch (\Throwable $e) {
            $this->log('Single-logout failure: ' . $e->getMessage(), Log::WARNING);
        }
    }

    // -----------------------------------------------------------------------
    // Flow handlers
    // -----------------------------------------------------------------------

    private function startLogin(CMSApplicationInterface $app): void
    {
        $returnUrl = $this->requestedReturnUrl($app);

        [, $client] = $this->connect();

        $state        = Client::randomToken();
        $nonce        = Client::randomToken();
        $codeVerifier = Client::randomToken();

        $app->getSession()->set(self::SESSION_AUTH, [
            'state'    => $state,
            'nonce'    => $nonce,
            'verifier' => $codeVerifier,
            'return'   => $returnUrl,
            'created'  => time(),
        ]);

        // Joomla's redirect persists the session on shutdown; a raw header()
        // + exit would not, which is why state must never bypass this path.
        $app->redirect($client->authorizationUrl($state, $nonce, $codeVerifier));
    }

    private function handleCallback(CMSApplicationInterface $app): void
    {
        $input   = $app->getInput();
        $session = $app->getSession();

        // One-shot: whatever happens below, this state can never be replayed.
        $pending = $session->get(self::SESSION_AUTH);
        $session->remove(self::SESSION_AUTH);
        $pending = \is_object($pending) ? (array) $pending : $pending;

        $error = (string) $input->getCmd('error', '');

        if ($error !== '') {
            throw new OidcException(sprintf(
                'IdP returned error "%s" (%s)',
                $error,
                self::logSafe((string) $input->getString('error_description', ''))
            ));
        }

        if (!\is_array($pending) || !isset($pending['state'], $pending['nonce'], $pending['verifier'], $pending['created'])) {
            throw new OidcException(
                'No pending authorization in the session (cookies blocked, session expired, or callback opened directly)'
            );
        }

        $code  = (string) $input->getString('code', '');
        $state = (string) $input->getString('state', '');

        if ($code === '' || $state === '' || !hash_equals((string) $pending['state'], $state)) {
            throw new OidcException('Authorization state mismatch');
        }

        if (time() - (int) $pending['created'] > self::AUTH_MAX_AGE) {
            throw new OidcException('Pending authorization is older than ' . self::AUTH_MAX_AGE . ' seconds');
        }

        [$discovery, $client] = $this->connect();

        $tokens = $client->exchangeCode($code, (string) $pending['verifier']);
        $claims = (new TokenVerifier($discovery->issuer, $this->clientId()))
            ->verify($tokens['id_token'], $client->fetchJwks(), (string) $pending['nonce']);
        $claims = $this->mergeUserinfo($client, $tokens, $claims);

        $matchField   = $this->params->get('match_field', 'username');
        $usernameAttr = $this->params->get('claim_username', 'preferred_username');
        $emailAttr    = $this->params->get('claim_email', 'email');
        $nameAttr     = $this->params->get('claim_name', 'name');

        $username = $this->claim($claims, $usernameAttr);
        $email    = $this->claim($claims, $emailAttr);
        $name     = $this->claim($claims, $nameAttr) ?: $username ?: $email;

        if ($matchField === 'email') {
            if (!$email) {
                throw new OidcException('IdP did not return an email claim');
            }
            $userId = $this->findUserIdByEmail($email);
        } else {
            if (!$username) {
                throw new OidcException('IdP did not return a username claim');
            }
            $userId = UserHelper::getUserId($username);
        }

        if (!$userId) {
            $userId = $this->maybeAutoCreate($username, $email, $name);
        }

        if (!$userId) {
            $this->log(sprintf(
                'Match-only: no Joomla user found for match_field=%s claim_username=%s username=%s email=%s. Claim keys seen: %s',
                $matchField,
                $usernameAttr,
                $username ?? '(null)',
                $email ?? '(null)',
                implode(',', array_keys($claims))
            ), Log::WARNING);

            $app->enqueueMessage(Text::_('PLG_SYSTEM_HQOIDC_ERR_USER_NOT_PROVISIONED'), 'warning');
            $app->redirect(Uri::root());

            return;
        }

        $user = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($userId);

        if ($user->block) {
            $this->log('Blocked user attempted OIDC login: id=' . (int) $user->id . ' username=' . $user->username, Log::WARNING);
            $app->enqueueMessage(Text::_('PLG_SYSTEM_HQOIDC_ERR_USER_BLOCKED'), 'error');
            $app->redirect(Uri::root());

            return;
        }

        $options = [
            'action'       => 'core.login.site',
            'remember'     => true,
            'silent'       => true,
            'responseType' => 'hqoidc',
            'autoregister' => false,
        ];

        // We bypass $app->login() (which runs the authentication plugin chain and
        // would reject us for not supplying a password). Instead we replicate the
        // post-authentication portion: import user plugins and trigger onUserLogin,
        // which plg_user_joomla handles by establishing the Joomla session.
        $response                 = new \stdClass();
        $response->status         = Authentication::STATUS_SUCCESS;
        $response->type           = 'hqoidc';
        $response->username       = $user->username;
        $response->email          = $user->email;
        $response->fullname       = $user->name;
        $response->password_clear = '';

        PluginHelper::importPlugin('user');

        $results = $app->triggerEvent('onUserLogin', [(array) $response, $options]);

        if (\in_array(false, $results, true)) {
            throw new \RuntimeException('A user plugin denied the OIDC login');
        }

        $app->triggerEvent('onUserAfterLogin', [$options]);

        // Kept for RP-initiated logout. Set after login so it lives in the
        // session plg_user_joomla just established.
        $session->set(self::SESSION_ID_TOKEN, $tokens['id_token']);

        $returnUrl = $pending['return'] ?? null;

        if (!\is_string($returnUrl) || !$this->isSafeReturnUrl($returnUrl)) {
            $this->log('callback: no usable return URL, falling back to post_login_url');
            $returnUrl = $this->params->get('post_login_url', '/') ?: '/';
        }

        $this->log('callback: redirecting to ' . self::logSafe($returnUrl));
        $app->redirect($this->absoluteUrl($returnUrl));
    }

    private function handleLogout(CMSApplicationInterface $app): void
    {
        $user = $app->getIdentity();

        if ($user && !$user->guest) {
            // Triggers onUserLogout/onUserAfterLogout which, with single_logout on, redirect to the IdP.
            $app->logout();
        }

        // Fallthrough: no identity, or single_logout disabled, or no id_token stored.
        $app->redirect($this->absoluteUrl($this->params->get('post_logout_url', '/') ?: '/'));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * @return array{0: Discovery, 1: Client}
     */
    private function connect(): array
    {
        $issuer = rtrim((string) $this->params->get('issuer_url', ''), '/');

        if ($issuer === '' || $this->clientId() === '') {
            throw new OidcException('HQ OIDC is not configured (issuer_url and client_id required)');
        }

        $http      = JoomlaHttpClient::create();
        $discovery = Discovery::fetch($http, $issuer);
        $scopes    = preg_split('/\s+/', (string) $this->params->get('scopes', 'openid profile email')) ?: [];

        $client = new Client(
            $http,
            $discovery,
            $this->clientId(),
            (string) $this->params->get('client_secret', '') ?: null,
            rtrim(Uri::root(), '/') . '/index.php?option=hqoidc&task=callback',
            array_values(array_filter($scopes))
        );

        return [$discovery, $client];
    }

    private function clientId(): string
    {
        return (string) $this->params->get('client_id', '');
    }

    /**
     * Userinfo is supplementary: providers like Okta keep profile claims out
     * of the ID token. A transport failure therefore degrades to ID token
     * claims only, but a sub mismatch is fatal (OIDC Core 5.3.2).
     *
     * @param array<string, mixed> $tokens
     * @param array<string, mixed> $claims
     *
     * @return array<string, mixed>
     */
    private function mergeUserinfo(Client $client, array $tokens, array $claims): array
    {
        $accessToken = $tokens['access_token'] ?? null;

        if (!\is_string($accessToken) || $accessToken === '') {
            return $claims;
        }

        try {
            $userinfo = $client->fetchUserinfo($accessToken);
        } catch (\RuntimeException $e) {
            $this->log('userinfo skipped: ' . $e->getMessage(), Log::WARNING);

            return $claims;
        }

        if ($userinfo === null) {
            return $claims;
        }

        if (($userinfo['sub'] ?? null) !== $claims['sub']) {
            throw new OidcException('Userinfo "sub" does not match the ID token');
        }

        // ID token claims are signature-verified, so they win on conflict.
        return array_merge($userinfo, $claims);
    }

    /**
     * The ?return= parameter, validated. Joomla's own login flows pass return
     * URLs base64-encoded, but a raw relative path like "/foo/bar" can be
     * coincidentally valid base64, so the URL-shape check comes first.
     */
    private function requestedReturnUrl(CMSApplicationInterface $app): ?string
    {
        $return = (string) $app->getInput()->getString('return', '');

        if ($return === '') {
            return null;
        }

        $looksLikeUrl = str_starts_with($return, '/') || preg_match('#^https?://#i', $return) === 1;
        $candidate    = $return;

        if (!$looksLikeUrl) {
            $decoded = base64_decode($return, true);

            if ($decoded !== false) {
                $candidate = $decoded;
            }
        }

        $safe = $this->isSafeReturnUrl($candidate);
        $this->log(sprintf('login: return candidate=%s safe=%s', self::logSafe($candidate), $safe ? 'yes' : 'no'));

        return $safe ? $candidate : null;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function claim(array $claims, string $key): ?string
    {
        $value = $claims[$key] ?? null;

        if ($value === null || $value === '') {
            return null;
        }

        return \is_scalar($value) ? (string) $value : null;
    }

    private function findUserIdByEmail(string $email): int
    {
        $db = Factory::getContainer()->get(DatabaseInterface::class);
        $q  = $db->getQuery(true)
            ->select($db->quoteName('id'))
            ->from($db->quoteName('#__users'))
            ->where($db->quoteName('email') . ' = :email')
            ->bind(':email', $email)
            ->setLimit(1);

        return (int) $db->setQuery($q)->loadResult();
    }

    private function maybeAutoCreate(?string $username, ?string $email, ?string $name): int
    {
        if ($this->params->get('provisioning', 'match_only') !== 'auto_create') {
            return 0;
        }

        if (!$username && !$email) {
            return 0;
        }

        // Fall back to email-as-username if no username claim available.
        $finalUsername = $username ?: $email;
        if (!$email) {
            return 0;
        }

        $defaultGroup = (int) $this->params->get('default_user_group', 2);
        if ($defaultGroup <= 0) {
            $defaultGroup = 2;
        }

        $data = [
            'name'      => $name ?: $finalUsername,
            'username'  => $finalUsername,
            'email'     => $email,
            'password'  => UserHelper::genRandomPassword(32),
            'password2' => null,
            'block'     => 0,
            'sendEmail' => 0,
            'groups'    => [$defaultGroup],
            'registerDate' => Factory::getDate()->toSql(),
        ];
        $data['password2'] = $data['password'];

        $user = new User();
        if (!$user->bind($data)) {
            throw new \RuntimeException('User bind failed: ' . $user->getError());
        }
        if (!$user->save()) {
            throw new \RuntimeException('User save failed: ' . $user->getError());
        }

        return (int) $user->id;
    }

    private function isSafeReturnUrl(string $url): bool
    {
        if ($url === '') {
            return false;
        }

        // Same-origin or relative paths only.
        if (str_starts_with($url, '/') && !str_starts_with($url, '//')) {
            return true;
        }

        $host    = parse_url($url, PHP_URL_HOST);
        $rootHost = parse_url(Uri::root(), PHP_URL_HOST);

        return $host !== null && $rootHost !== null && strcasecmp($host, $rootHost) === 0;
    }

    private function absoluteUrl(string $url): string
    {
        if ($url === '' || $url === '/') {
            return Uri::root();
        }

        if (preg_match('#^https?://#i', $url)) {
            return $url;
        }

        return rtrim(Uri::root(), '/') . '/' . ltrim($url, '/');
    }

    private function ensureVendorAutoload(): void
    {
        if (class_exists(JWT::class, false)) {
            return;
        }

        $autoload = __DIR__ . '/../../vendor/autoload.php';

        if (!is_file($autoload)) {
            throw new \RuntimeException('HQ OIDC vendor/ is missing — reinstall the plugin package');
        }

        require_once $autoload;
    }

    /**
     * Strip control characters and cap length before request-supplied
     * values reach the log file.
     */
    private static function logSafe(string $value): string
    {
        return substr(preg_replace('/[\x00-\x1F\x7F]+/', ' ', $value) ?? '', 0, 200);
    }

    private function log(string $message, int $priority = Log::INFO): void
    {
        if ((int) $this->params->get('debug_log', 0) !== 1 && $priority < Log::WARNING) {
            return;
        }

        static $registered = false;
        if (!$registered) {
            Log::addLogger(
                ['text_file' => 'hqoidc.log'],
                Log::ALL,
                ['plg_system_hqoidc']
            );
            $registered = true;
        }

        Log::add($message, $priority, 'plg_system_hqoidc');
    }
}
