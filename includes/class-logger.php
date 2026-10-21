<?php
if (!defined('ABSPATH')) {
    exit;
}

class Human_Guard_Logger {

    public static function get_table_name() {
        global $wpdb;
        return $wpdb->prefix . 'human_guard_bot_logs';
    }

    public static function create_table() {
        global $wpdb;
        $table_name = self::get_table_name();
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL DEFAULT '',
            event_type VARCHAR(30) NOT NULL DEFAULT '',
            block_reason VARCHAR(100) NOT NULL DEFAULT '',
            user_identifier VARCHAR(150) NOT NULL DEFAULT '',
            user_agent VARCHAR(500) NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_ip (ip_address),
            KEY idx_event (event_type),
            KEY idx_created (created_at)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);

        // Initialize stats if not present
        if (!get_option('human_guard_stats')) {
            update_option('human_guard_stats', [
                'total_blocked_regs'   => 0,
                'total_blocked_logins' => 0,
                'total_blocked_xmlrpc' => 0,
                'total_blocked_other'  => 0,
                'last_blocked_at'      => null,
            ]);
        }
    }

    public static function log($event_type, $reason, $user_identifier = '') {
        global $wpdb;

        $ip = self::get_client_ip();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])), 0, 500) : '';
        $user_identifier = substr(sanitize_text_field($user_identifier), 0, 150);
        $reason = substr(sanitize_text_field($reason), 0, 100);
        $event_type = substr(sanitize_text_field($event_type), 0, 30);

        $table_name = self::get_table_name();
        $wpdb->insert(
            $table_name,
            [
                'ip_address'      => $ip,
                'event_type'      => $event_type,
                'block_reason'    => $reason,
                'user_identifier' => $user_identifier,
                'user_agent'      => $ua,
                'created_at'      => current_time('mysql'),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s']
        );

        // Update stats
        $stats = get_option('human_guard_stats', [
            'total_blocked_regs'   => 0,
            'total_blocked_logins' => 0,
            'total_blocked_xmlrpc' => 0,
            'total_blocked_other'  => 0,
            'last_blocked_at'      => null,
        ]);

        if ($event_type === 'registration') {
            $stats['total_blocked_regs'] = ($stats['total_blocked_regs'] ?? 0) + 1;
        } elseif ($event_type === 'login') {
            $stats['total_blocked_logins'] = ($stats['total_blocked_logins'] ?? 0) + 1;
        } elseif ($event_type === 'xmlrpc') {
            $stats['total_blocked_xmlrpc'] = ($stats['total_blocked_xmlrpc'] ?? 0) + 1;
        } else {
            $stats['total_blocked_other'] = ($stats['total_blocked_other'] ?? 0) + 1;
        }

        $stats['last_blocked_at'] = current_time('mysql');
        update_option('human_guard_stats', $stats, false);

        // Auto prune if over 1500 logs (1 in 50 chance to avoid overhead)
        if (mt_rand(1, 50) === 1) {
            self::prune_logs();
        }
    }

    public static function get_recent_logs($limit = 100) {
        global $wpdb;
        $table_name = self::get_table_name();
        $limit = max(1, min(500, intval($limit)));
        return $wpdb->get_results("SELECT * FROM $table_name ORDER BY id DESC LIMIT $limit", ARRAY_A);
    }

    public static function get_stats() {
        return get_option('human_guard_stats', [
            'total_blocked_regs'   => 0,
            'total_blocked_logins' => 0,
            'total_blocked_xmlrpc' => 0,
            'total_blocked_other'  => 0,
            'last_blocked_at'      => null,
        ]);
    }

    public static function clear_logs() {
        global $wpdb;
        $table_name = self::get_table_name();
        $wpdb->query("TRUNCATE TABLE $table_name");
        return true;
    }

    public static function prune_logs($keep = 1000) {
        global $wpdb;
        $table_name = self::get_table_name();
        $count = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_name");
        if ($count > $keep) {
            $offset = $count - $keep;
            $wpdb->query("DELETE FROM $table_name ORDER BY id ASC LIMIT $offset");
        }
    }

    public static function get_client_ip() {
        $ip_keys = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_REAL_IP',        // CyberPanel / LiteSpeed reverse proxy
            'HTTP_X_FORWARDED_FOR',  // Standard proxy
            'REMOTE_ADDR'            // Direct connection
        ];

        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                $clean_ip = trim($ips[0]);
                if (filter_var($clean_ip, FILTER_VALIDATE_IP)) {
                    return $clean_ip;
                }
            }
        }

        return '127.0.0.1';
    }
}
