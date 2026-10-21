<?php
/**
 * Plugin Name: HumanGuard - Anti-Bot & Registration Security
 * Plugin URI:  https://zohodigital.com
 * Description: Advanced multi-layer anti-bot & registration security plugin for WordPress, Tutor LMS, and WooCommerce. Built by zohodigital.com.
 * Version:     1.0.0
 * Author:      zohodigital.com
 * Author URI:  https://zohodigital.com
 * Text Domain: wp-human-guard
 * License:     GPL-2.0+
 */

if (!defined('ABSPATH')) {
    exit;
}

define('HUMAN_GUARD_VERSION', '1.0.0');
define('HUMAN_GUARD_PATH', plugin_dir_path(__FILE__));
define('HUMAN_GUARD_URL', plugin_dir_url(__FILE__));

// Load dependencies
require_once HUMAN_GUARD_PATH . 'includes/class-logger.php';
require_once HUMAN_GUARD_PATH . 'includes/class-security-core.php';
require_once HUMAN_GUARD_PATH . 'includes/class-hooks.php';
require_once HUMAN_GUARD_PATH . 'includes/class-admin.php';

// Plugin Activation
register_activation_hook(__FILE__, 'human_guard_activate');
function human_guard_activate() {
    Human_Guard_Logger::create_table();
    
    // Save default settings if not exists
    if (!get_option(Human_Guard_Core::OPTION_SETTINGS)) {
        Human_Guard_Core::update_settings([]);
    }
}

// Initialize Plugin
function human_guard_init() {
    Human_Guard_Hooks::init();

    if (is_admin()) {
        Human_Guard_Admin::init();
    }
}
add_action('plugins_loaded', 'human_guard_init', 5);
