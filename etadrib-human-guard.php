<?php
/**
 * Plugin Name: Etadrib Human Guard (حارس إتدريب)
 * Plugin URI:  https://etadrib.com
 * Description: نظام متقدم متعدد الطبقات للحماية ضد البوتات والتسجيلات الوهمية وهجمات التخمين، وحصر التسجيل للبشر الحقيقيين فقط.
 * Version:     1.0.0
 * Author:      Etadrib Security Engineering
 * Text Domain: etadrib-human-guard
 * License:     GPL-2.0+
 */

if (!defined('ABSPATH')) {
    exit;
}

define('ETADRIB_GUARD_VERSION', '1.0.0');
define('ETADRIB_GUARD_PATH', plugin_dir_path(__FILE__));
define('ETADRIB_GUARD_URL', plugin_dir_url(__FILE__));

// Load dependencies
require_once ETADRIB_GUARD_PATH . 'includes/class-logger.php';
require_once ETADRIB_GUARD_PATH . 'includes/class-security-core.php';
require_once ETADRIB_GUARD_PATH . 'includes/class-hooks.php';
require_once ETADRIB_GUARD_PATH . 'includes/class-admin.php';

// Plugin Activation
register_activation_hook(__FILE__, 'etadrib_guard_activate');
function etadrib_guard_activate() {
    Etadrib_Guard_Logger::create_table();
    
    // Save default settings if not exists
    if (!get_option(Etadrib_Guard_Core::OPTION_SETTINGS)) {
        Etadrib_Guard_Core::update_settings([]);
    }
}

// Initialize Plugin
function etadrib_guard_init() {
    Etadrib_Guard_Hooks::init();

    if (is_admin()) {
        Etadrib_Guard_Admin::init();
    }
}
add_action('plugins_loaded', 'etadrib_guard_init', 5);
