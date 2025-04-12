<?php
declare(strict_types=1);
namespace Vladyslav10111\CrossDomainLogin;

defined('ABSPATH') || exit;

class SettingsPage {
    private $log_file;

    public function __construct() {
        $this->log_file = WP_CONTENT_DIR . '/cdl-debug.log';
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_notices', [$this, 'no_domains_notice']);
    }

    // Adds settings page to admin menu
    public function add_settings_page(): void {
        add_options_page(
            __('Cross Domain Login Settings', 'cross-domain-login'),
            __('Cross Domain Login', 'cross-domain-login'),
            'manage_options',
            'cross-domain-login',
            [$this, 'render_settings_page']
        );
    }

    // Registers settings
    public function register_settings(): void {
        register_setting('cdl_settings_group', 'cdl_domains', [
            'sanitize_callback' => [$this, 'sanitize_domains'],
        ]);

        add_settings_section(
            'cdl_domains_section',
            __('Domains Configuration', 'cross-domain-login'),
            null,
            'cross-domain-login'
        );

        for ($i = 1; $i <= 5; $i++) {
            add_settings_field(
                'cdl_domain_' . $i,
                sprintf(__('Domain %d', 'cross-domain-login'), $i),
                [$this, 'render_domain_field'],
                'cross-domain-login',
                'cdl_domains_section',
                ['index' => $i]
            );
        }
    }

    // Sanitizes domains
    public function sanitize_domains(array $input): array {
        $sanitized = [];
        $errors = [];

        foreach ($input as $index => $domain) {
            $domain = trim($domain);
            if (!empty($domain)) {
                if ($this->is_valid_domain($domain)) {
                    $sanitized[$index] = sanitize_text_field($domain);
                } else {
                    $errors[] = sprintf(__('Invalid domain format: %s. Use format like example.com', 'cross-domain-login'), $domain);
                }
            }
        }

        // Check for unique domains
        $unique_domains = array_unique($sanitized);
        if (count($unique_domains) < count($sanitized)) {
            $errors[] = __('Domains must be unique.', 'cross-domain-login');
            $sanitized = $unique_domains;
        }

        // Require at least one domain
        if (empty($sanitized)) {
            $errors[] = __('At least one domain must be provided.', 'cross-domain-login');
            $sanitized = [];
        }

        foreach ($errors as $error) {
            add_settings_error(
                'cdl_domains',
                'cdl_domains_error',
                $error,
                'error'
            );
        }

        $this->log_message('Sanitized domains: ' . json_encode($sanitized));
        return $sanitized;
    }

    // Checks if a string is a valid domain
    private function is_valid_domain(string $domain): bool {
        return preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $domain) && !preg_match('/^(https?:\/\/|\/)/', $domain);
    }

    // Renders domain input field
    public function render_domain_field(array $args): void {
        $index = $args['index'];
        $domains = get_option('cdl_domains', []);
        $value = isset($domains[$index]) ? esc_attr($domains[$index]) : '';
        ?>
        <input type="text" name="cdl_domains[<?php echo esc_attr($index); ?>]" value="<?php echo $value; ?>" class="regular-text" placeholder="example.com" />
        <p class="description"><?php _e('Enter a domain (e.g., example.com). Leave empty if not used.', 'cross-domain-login'); ?></p>
        <?php
    }

    // Renders settings page
    public function render_settings_page(): void {
        ?>
        <div class="wrap">
            <h1><?php _e('Cross Domain Login Settings', 'cross-domain-login'); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('cdl_settings_group');
                do_settings_sections('cross-domain-login');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }

    // Shows notice if no domains configured
    public function no_domains_notice(): void {
        $saved_domains = get_option('cdl_domains', []);
        if (!empty($saved_domains)) {
            return;
        }
        ?>
        <div class="notice notice-error">
            <p><?php _e('Please configure at least one domain in <a href="' . admin_url('options-general.php?page=cross-domain-login') . '">Cross Domain Login settings</a>.', 'cross-domain-login'); ?></p>
        </div>
        <?php
    }

    // Logs a message to file if WP_DEBUG is enabled
    private function log_message(string $message): void {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }
        $timestamp = current_time('mysql');
        file_put_contents($this->log_file, "[$timestamp] SettingsPage: $message\n", FILE_APPEND);
    }
}