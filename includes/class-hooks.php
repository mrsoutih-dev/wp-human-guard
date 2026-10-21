<?php
if (!defined('ABSPATH')) {
    exit;
}

class Human_Guard_Hooks {

    public static function init() {
        $settings = Human_Guard_Core::get_settings();

        // 1. XML-RPC Blocker
        if (!empty($settings['block_xmlrpc'])) {
            self::setup_xmlrpc_blocker();
        }

        // 2. Asset Enqueues
        add_action('login_enqueue_scripts', [__CLASS__, 'enqueue_assets']);
        add_action('wp_enqueue_scripts', [__CLASS__, 'enqueue_assets']);

        // 3. WordPress Core Registration
        add_action('register_form', [__CLASS__, 'render_registration_fields']);
        add_filter('registration_errors', [__CLASS__, 'validate_registration_errors'], 20, 3);

        // 4. WordPress Core Login
        add_action('login_form', [__CLASS__, 'render_login_fields']);
        add_filter('authenticate', [__CLASS__, 'validate_login_authenticate'], 5, 3);
        add_action('wp_login_failed', [__CLASS__, 'handle_login_failed']);
        add_action('wp_login', [__CLASS__, 'handle_login_success'], 10, 2);

        // 5. Lost Password
        add_action('lostpassword_form', [__CLASS__, 'render_registration_fields']);
        add_action('lostpassword_post', [__CLASS__, 'validate_lostpassword_post']);

        // 6. Tutor LMS Integration
        add_action('tutor_student_reg_form', [__CLASS__, 'render_registration_fields']);
        add_action('tutor_instructor_reg_form', [__CLASS__, 'render_registration_fields']);
        add_filter('tutor_student_register_validation_errors', [__CLASS__, 'validate_tutor_registration'], 20, 1);
        add_filter('tutor_instructor_register_validation_errors', [__CLASS__, 'validate_tutor_registration'], 20, 1);

        // 7. WooCommerce Integration
        add_action('woocommerce_register_form', [__CLASS__, 'render_registration_fields']);
        add_filter('woocommerce_registration_errors', [__CLASS__, 'validate_wc_registration'], 20, 3);
        add_action('woocommerce_login_form', [__CLASS__, 'render_login_fields']);
        add_filter('woocommerce_process_login_errors', [__CLASS__, 'validate_wc_login'], 20, 3);
    }

    public static function enqueue_assets() {
        wp_register_style(
            'human-guard-css',
            HUMAN_GUARD_URL . 'assets/css/human-guard.css',
            [],
            HUMAN_GUARD_VERSION
        );
        wp_enqueue_style('human-guard-css');

        wp_register_script(
            'human-guard-js',
            HUMAN_GUARD_URL . 'assets/js/human-guard.js',
            [],
            HUMAN_GUARD_VERSION,
            true
        );
        wp_enqueue_script('human-guard-js');
    }

    /* ── XML-RPC Protection ────────────────────────────────────────── */

    private static function setup_xmlrpc_blocker() {
        add_filter('xmlrpc_enabled', '__return_false');
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');

        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        if (defined('XMLRPC_REQUEST') || stripos($uri, 'xmlrpc.php') !== false) {
            Human_Guard_Logger::log('xmlrpc', 'xmlrpc_direct_hit_blocked');
            status_header(403);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-cache, no-store, must-revalidate');
            exit('403 Forbidden: XML-RPC service is disabled for security reasons.');
        }
    }

    /* ── Registration Callbacks ────────────────────────────────────── */

    public static function render_registration_fields() {
        Human_Guard_Core::render_form_fields('registration');
    }

    public static function validate_registration_errors($errors, $sanitized_user_login, $user_email) {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return $errors;
        }

        $identifier = !empty($user_email) ? $user_email : $sanitized_user_login;
        $check = Human_Guard_Core::verify_submission('registration', $identifier);

        if (is_wp_error($check)) {
            $errors->add($check->get_error_code(), $check->get_error_message());
        }

        return $errors;
    }

    /* ── Login Callbacks ───────────────────────────────────────────── */

    public static function render_login_fields() {
        Human_Guard_Core::render_form_fields('login');
    }

    public static function validate_login_authenticate($user, $username, $password) {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return $user;
        }

        if (empty($username) && empty($password)) {
            return $user;
        }

        $check = Human_Guard_Core::verify_submission('login', $username);
        if (is_wp_error($check)) {
            return $check;
        }

        return $user;
    }

    public static function handle_login_failed($username) {
        Human_Guard_Core::record_failed_login($username);
    }

    public static function handle_login_success($user_login, $user) {
        Human_Guard_Core::clear_failed_logins();
    }

    /* ── Lost Password Callbacks ───────────────────────────────────── */

    public static function validate_lostpassword_post($errors) {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return;
        }

        $user_data = isset($_POST['user_login']) ? sanitize_text_field(wp_unslash($_POST['user_login'])) : '';
        $check = Human_Guard_Core::verify_submission('lostpassword', $user_data);
        if (is_wp_error($check)) {
            if (is_wp_error($errors)) {
                $errors->add($check->get_error_code(), $check->get_error_message());
            }
        }
    }

    /* ── Tutor LMS Callbacks ───────────────────────────────────────── */

    public static function validate_tutor_registration($errors) {
        if (!is_array($errors)) {
            $errors = [];
        }

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST' || empty($_POST['tutor_action'])) {
            return $errors;
        }

        $email = isset($_POST['email']) ? sanitize_email(wp_unslash($_POST['email'])) : '';
        $check = Human_Guard_Core::verify_submission('registration', $email);

        if (is_wp_error($check)) {
            $errors['human_guard'] = $check->get_error_message();
        }

        return $errors;
    }

    /* ── WooCommerce Callbacks ─────────────────────────────────────── */

    public static function validate_wc_registration($errors, $username, $email) {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return $errors;
        }

        $identifier = !empty($email) ? $email : $username;
        $check = Human_Guard_Core::verify_submission('registration', $identifier);

        if (is_wp_error($check)) {
            $errors->add($check->get_error_code(), $check->get_error_message());
        }

        return $errors;
    }

    public static function validate_wc_login($validation_error, $username, $password) {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return $validation_error;
        }

        if (empty($username) && empty($password)) {
            return $validation_error;
        }

        $check = Human_Guard_Core::verify_submission('login', $username);
        if (is_wp_error($check)) {
            return $check;
        }

        return $validation_error;
    }
}
