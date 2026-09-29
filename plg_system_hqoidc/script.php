<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

\defined('_JEXEC') or die;

use Joomla\CMS\Installer\InstallerAdapter;
use Joomla\CMS\Installer\InstallerScriptInterface;
use Joomla\CMS\Log\Log;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;
use Joomla\Filesystem\Folder;

return new class () implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        $container->set(InstallerScriptInterface::class, new class () implements InstallerScriptInterface {
            /**
             * Shipped by 1.0.x (jumbojett/openid-connect-php and its phpseclib
             * dependency). Joomla's upgrade copies the new package over the old
             * files but never removes what the new package no longer contains.
             */
            private const STALE_VENDOR_DIRS = ['jumbojett', 'paragonie', 'phpseclib'];

            public function install(InstallerAdapter $adapter): bool
            {
                return true;
            }

            public function update(InstallerAdapter $adapter): bool
            {
                return true;
            }

            public function uninstall(InstallerAdapter $adapter): bool
            {
                return true;
            }

            public function preflight(string $type, InstallerAdapter $adapter): bool
            {
                return true;
            }

            public function postflight(string $type, InstallerAdapter $adapter): bool
            {
                $root = $adapter->getParent()->getPath('extension_root');

                if (!\is_string($root) || $root === '') {
                    $root = JPATH_PLUGINS . '/system/hqoidc';
                }

                foreach (self::STALE_VENDOR_DIRS as $dir) {
                    $path = $root . '/vendor/' . $dir;

                    if (!is_dir($path)) {
                        continue;
                    }

                    // A failed cleanup must never fail the install: the new
                    // files are already in place and nothing loads these.
                    try {
                        Folder::delete($path);
                    } catch (\Throwable $e) {
                        Log::add('Could not remove stale ' . $path . ': ' . $e->getMessage(), Log::WARNING, 'plg_system_hqoidc');
                    }
                }

                return true;
            }
        });
    }
};
