<?php
namespace Vladyslav10111\CrossDomainLogin;

use WP_User;

defined('ABSPATH') || exit;

class CrossDomainLogin {
    private $domains;
    private $log_file;

    public function __construct() {
        $this->log_file = WP_CONTENT_DIR . '/cdl-debug.log';
        $this->log_message('Constructing CrossDomainLogin');

        // Initialize domains
        try {
            $this->init_domains();
        } catch (Exception $e) {
            $this->log_message('Error initializing domains: ' . $e->getMessage());
            $this->domains = [];
        }

        // Register hooks if domains exist
        if (!empty($this->domains)) {
            $this->log_message('Plugin initialized. Domains: ' . implode(', ', $this->domains));
            $this->register_hooks();
        } else {
            $this->log_message('No domains configured.');
        }
    }

    // Initializes domains from settings
    private function init_domains(): void {
        $this->domains = [];
        $saved_domains = get_option('cdl_domains', []);

        // Ensure saved_domains is an array
        if (!is_array($saved_domains)) {
            $this->log_message('Invalid saved_domains format: ' . gettype($saved_domains));
            return;
        }

        // Load domains from settings
        foreach ($saved_domains as $domain) {
            if (!empty($domain) && is_string($domain) && $this->is_valid_domain($domain)) {
                $this->domains[] = sanitize_text_field($domain);
            }
        }
        $this->domains = array_unique($this->domains);
        sort($this->domains);
    }

    // Checks if a string is a valid domain
    private function is_valid_domain(string $domain): bool {
        return preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $domain) && !preg_match('/^(https?:\/\/|\/)/', $domain);
    }

    // Logs a message to file if WP_DEBUG is enabled
    private function log_message(string $message): void {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }
        $timestamp = current_time('mysql');
        file_put_contents($this->log_file, "[$timestamp] $message\n", FILE_APPEND);
    }

    // Registers hooks
    private function register_hooks(): void {
        add_action('wp_login', [$this, 'handle_login'], 10, 2);
        add_action('set_auth_cookie', [$this, 'handle_set_auth_cookie'], 10, 5);
        add_action('init', [$this, 'check_login_token'], 1);
        add_action('wp_logout', [$this, 'handle_logout']);
    }

    // Generates a token for a user
    private function generate_token(int $user_id): string {
        $time = time();
        $key = wp_generate_password(20, false);
        $token = hash('sha256', $user_id . $time . $key);
        update_user_meta($user_id, 'cdl_token', $token);
        update_user_meta($user_id, 'cdl_token_time', $time);
        $this->log_message("Token generated for user ID $user_id: $token");
        return $token;
    }

    // Gets the current domain
    private function get_current_domain(): string {
        $domain = !empty($_SERVER['HTTP_HOST']) ? sanitize_text_field($_SERVER['HTTP_HOST']) : parse_url(home_url(), PHP_URL_HOST);
        $this->log_message("Detected domain: $domain");
        return $domain;
    }

    // Handles login via wp_login
    public function handle_login(string $user_login, WP_User $user): void {
        $this->log_message("Login detected via wp_login for user: $user_login (ID: $user->ID)");
        $this->init_cross_domain_sync($user);
    }

    // Handles authentication cookie setting
    public function handle_set_auth_cookie(string $auth_cookie, int $expire, int $expiration, int $user_id, string $scheme): void {
        // Prevent duplicate calls
        static $processed = [];
        $key = $user_id . '-' . $scheme;
        if (isset($processed[$key])) {
            $this->log_message("Skipping duplicate set_auth_cookie for user ID: $user_id");
            return;
        }
        $processed[$key] = true;

        // Skip if sync redirect
        if (isset($_GET['cdl_token'])) {
            $this->log_message("Skipping handle_set_auth_cookie due to cdl_token presence");
            return;
        }

        $user = get_user_by('id', $user_id);
        if (!$user instanceof WP_User) {
            $this->log_message("No valid WP_User found for ID: $user_id in handle_set_auth_cookie");
            return;
        }

        $this->log_message("Login detected via set_auth_cookie for user: {$user->user_login} (ID: $user_id)");
        $this->init_cross_domain_sync($user);
    }

    // Starts cross-domain sync
    private function init_cross_domain_sync(WP_User $user): void {
        // Check if sync is in progress
        $is_syncing = get_user_meta($user->ID, 'cdl_syncing', true);
        if ($is_syncing) {
            $this->log_message("Sync already in progress for user ID: $user->ID");
            return;
        }

        // Mark sync start
        update_user_meta($user->ID, 'cdl_syncing', true);

        // Set cookie on initial domain
        wp_set_auth_cookie($user->ID, true, is_ssl());
        $this->log_message("Auth cookie set for user ID: $user->ID on initial domain");

        $token = $this->generate_token($user->ID);

        $current_domain = $this->get_current_domain();
        $this->log_message("Current domain: $current_domain");

        // Store origin and visited domains
        update_user_meta($user->ID, 'cdl_origin_domain', $current_domain);
        $visited = [$current_domain];
        update_user_meta($user->ID, 'cdl_visited_domains', $visited);
        $this->log_message("Initial visited domains: " . implode(', ', $visited));

        // Find next domain
        $next_domain = $this->get_next_domain($current_domain, $visited);
        if ($next_domain) {
            $protocol = is_ssl() ? 'https' : 'http';
            $redirect_url = "$protocol://$next_domain/?cdl_token=$token";
            $this->log_message("Redirecting to: $redirect_url");
            wp_redirect($redirect_url);
            exit;
        } else {
            $this->log_message("No more domains to sync, staying on $current_domain");
            delete_user_meta($user->ID, 'cdl_visited_domains');
            delete_user_meta($user->ID, 'cdl_token');
            delete_user_meta($user->ID, 'cdl_token_time');
            delete_user_meta($user->ID, 'cdl_origin_domain');
            delete_user_meta($user->ID, 'cdl_syncing');
        }
    }

    // Finds the next unvisited domain
    private function get_next_domain(string $current_domain, array $visited): ?string {
        $this->log_message("Visited domains in get_next_domain: " . (empty($visited) ? 'none' : implode(', ', $visited)));

        foreach ($this->domains as $domain) {
            if ($domain !== $current_domain && !in_array($domain, $visited)) {
                $this->log_message("Selected next domain: $domain");
                return $domain;
            }
        }
        $this->log_message("No unvisited domains found");
        return null;
    }

    // Checks token and logs in user
    public function check_login_token(): void {
        if (!isset($_GET['cdl_token'])) {
            return;
        }

        $token = sanitize_text_field($_GET['cdl_token']);
        $this->log_message("Token found in URL: $token");

        $users = get_users([
            'meta_key' => 'cdl_token',
            'meta_value' => $token,
            'number' => 1,
        ]);

        if (empty($users)) {
            $this->log_message('No user found for token');
            wp_redirect(home_url());
            exit;
        }

        $user = $users[0];
        $token_time = get_user_meta($user->ID, 'cdl_token_time', true);
        $this->log_message("User found for token: ID $user->ID, token time: $token_time");

        if (!$token_time || (time() - (int)$token_time > 60)) {
            $this->log_message('Token expired or invalid');
            delete_user_meta($user->ID, 'cdl_token');
            delete_user_meta($user->ID, 'cdl_token_time');
            delete_user_meta($user->ID, 'cdl_visited_domains');
            delete_user_meta($user->ID, 'cdl_origin_domain');
            delete_user_meta($user->ID, 'cdl_syncing');
            wp_redirect(home_url());
            exit;
        }

        // Log in user
        $this->log_message("Token valid, logging in user ID: $user->ID");
        wp_set_auth_cookie($user->ID, true, is_ssl());

        // Update visited domains
        $current_domain = $this->get_current_domain();
        $visited = get_user_meta($user->ID, 'cdl_visited_domains', true);
        if (!is_array($visited)) {
            $visited = [];
        }
        if (!in_array($current_domain, $visited)) {
            $visited[] = $current_domain;
            update_user_meta($user->ID, 'cdl_visited_domains', array_unique($visited));
            $this->log_message("Updated visited domains: " . implode(', ', $visited));
        } else {
            $this->log_message("Domain $current_domain already visited, skipping addition");
            // Prevent loops
            delete_user_meta($user->ID, 'cdl_token');
            delete_user_meta($user->ID, 'cdl_token_time');
            delete_user_meta($user->ID, 'cdl_visited_domains');
            delete_user_meta($user->ID, 'cdl_origin_domain');
            delete_user_meta($user->ID, 'cdl_syncing');
            wp_set_auth_cookie($user->ID, true, is_ssl());
            $this->log_message("Re-set auth cookie for user ID: $user->ID to ensure login");
            wp_redirect(home_url());
            exit;
        }

        // Find next domain
        $next_domain = $this->get_next_domain($current_domain, $visited);
        if ($next_domain) {
            $protocol = is_ssl() ? 'https' : 'http';
            $redirect_url = "$protocol://$next_domain/?cdl_token=$token";
            $this->log_message("Redirecting to next domain: $redirect_url");
            wp_set_auth_cookie($user->ID, true, is_ssl());
            wp_redirect($redirect_url);
            exit;
        }

        // Return to origin domain
        $origin_domain = get_user_meta($user->ID, 'cdl_origin_domain', true);
        $protocol = is_ssl() ? 'https' : 'http';
        $redirect_url = $origin_domain ? "$protocol://$origin_domain/" : home_url();
        $this->log_message("Returning to origin domain: $redirect_url");

        // Re-set cookie
        wp_set_auth_cookie($user->ID, true, is_ssl());
        $this->log_message("Final auth cookie set for user ID: $user->ID on origin domain");

        // Clean up metadata
        delete_user_meta($user->ID, 'cdl_token');
        delete_user_meta($user->ID, 'cdl_token_time');
        delete_user_meta($user->ID, 'cdl_visited_domains');
        delete_user_meta($user->ID, 'cdl_origin_domain');
        delete_user_meta($user->ID, 'cdl_syncing');

        wp_redirect($redirect_url);
        exit;
    }

    // Clears tokens on logout
    public function handle_logout(): void {
        $this->log_message('Logout detected');
        $user_id = get_current_user_id();
        delete_user_meta($user_id, 'cdl_token');
        delete_user_meta($user_id, 'cdl_token_time');
        delete_user_meta($user_id, 'cdl_visited_domains');
        delete_user_meta($user_id, 'cdl_origin_domain');
        delete_user_meta($user_id, 'cdl_syncing');
    }
}