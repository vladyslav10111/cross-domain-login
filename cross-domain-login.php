<?php
/*
Plugin Name: Cross Domain Login
Description: Enables cross-domain login for WordPress sites with configurable domains.
Version: 1.16
Author: Vladyslav10111
License: GPL2
*/

// Prevents direct access to the file
defined('ABSPATH') || exit;

// Includes Composer autoloader
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
} else {
    // Shows error in admin if Composer autoloader is missing
    add_action('admin_notices', function () {
        ?>
        <div class="notice notice-error">
            <p><?php _e('Cross Domain Login: Composer autoloader not found. Please run <code>composer install</code> in the plugin directory.', 'cross-domain-login'); ?></p>
        </div>
        <?php
    });
    return;
}

// Initializes classes
use Vladyslav10111\CrossDomainLogin\CrossDomainLogin;
use Vladyslav10111\CrossDomainLogin\SettingsPage;

new CrossDomainLogin();
new SettingsPage();