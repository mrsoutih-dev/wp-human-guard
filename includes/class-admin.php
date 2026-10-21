<?php
if (!defined('ABSPATH')) {
    exit;
}

class Etadrib_Guard_Admin {

    public static function init() {
        add_action('admin_menu', [__CLASS__, 'register_admin_menu']);
        add_action('admin_init', [__CLASS__, 'handle_admin_actions']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_admin_assets']);
    }

    public static function register_admin_menu() {
        add_menu_page(
            'حارس إتدريب - الحماية ضد البوتات',
            'حارس إتدريب (Guard)',
            'manage_options',
            'etadrib-human-guard',
            [__CLASS__, 'render_admin_dashboard'],
            'dashicons-shield-alt',
            80
        );
    }

    public static function enqueue_admin_assets($hook) {
        if (strpos($hook, 'etadrib-human-guard') === false) {
            return;
        }

        wp_enqueue_style(
            'etadrib-guard-admin-css',
            ETADRIB_GUARD_URL . 'assets/css/etadrib-guard.css',
            [],
            ETADRIB_GUARD_VERSION
        );
    }

    public static function handle_admin_actions() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Save Settings
        if (isset($_POST['et_guard_save_settings']) && check_admin_referer('et_guard_settings_nonce', '_et_nonce')) {
            $settings = [
                'honeypot_enabled'         => isset($_POST['honeypot_enabled']) ? 1 : 0,
                'time_trap_enabled'        => isset($_POST['time_trap_enabled']) ? 1 : 0,
                'min_time_seconds'         => max(1, min(10, intval($_POST['min_time_seconds'] ?? 2))),
                'js_token_enabled'         => isset($_POST['js_token_enabled']) ? 1 : 0,
                'math_challenge_enabled'   => isset($_POST['math_challenge_enabled']) ? 1 : 0,
                'math_for_login'           => isset($_POST['math_for_login']) ? 1 : 0,
                'block_disposable_emails'  => isset($_POST['block_disposable_emails']) ? 1 : 0,
                'rate_limit_registrations' => isset($_POST['rate_limit_registrations']) ? 1 : 0,
                'rate_limit_logins'        => isset($_POST['rate_limit_logins']) ? 1 : 0,
                'block_xmlrpc'             => isset($_POST['block_xmlrpc']) ? 1 : 0,
                'turnstile_enabled'        => isset($_POST['turnstile_enabled']) ? 1 : 0,
                'turnstile_site_key'       => sanitize_text_field(wp_unslash($_POST['turnstile_site_key'] ?? '')),
                'turnstile_secret_key'     => sanitize_text_field(wp_unslash($_POST['turnstile_secret_key'] ?? '')),
            ];

            Etadrib_Guard_Core::update_settings($settings);
            wp_safe_redirect(add_query_arg(['page' => 'etadrib-human-guard', 'tab' => 'settings', 'updated' => '1'], admin_url('admin.php')));
            exit;
        }

        // Clear Logs
        if (isset($_POST['et_guard_clear_logs']) && check_admin_referer('et_guard_clear_logs_nonce', '_et_nonce')) {
            Etadrib_Guard_Logger::clear_logs();
            wp_safe_redirect(add_query_arg(['page' => 'etadrib-human-guard', 'tab' => 'logs', 'cleared' => '1'], admin_url('admin.php')));
            exit;
        }

        // Bulk Delete Suspicious Users
        if (isset($_POST['et_guard_bulk_delete_users']) && check_admin_referer('et_guard_delete_users_nonce', '_et_nonce')) {
            $user_ids = isset($_POST['selected_users']) && is_array($_POST['selected_users']) ? array_map('intval', $_POST['selected_users']) : [];
            $deleted_count = 0;

            require_once ABSPATH . 'wp-admin/includes/user.php';

            foreach ($user_ids as $uid) {
                // ABSOLUTE SECURITY: Never delete administrator, current user, or user ID 1
                if ($uid === 1 || $uid === get_current_user_id() || user_can($uid, 'manage_options') || user_can($uid, 'tutor_instructor')) {
                    continue;
                }

                if (wp_delete_user($uid)) {
                    $deleted_count++;
                }
            }

            wp_safe_redirect(add_query_arg([
                'page' => 'etadrib-human-guard',
                'tab'  => 'cleanup',
                'deleted' => $deleted_count
            ], admin_url('admin.php')));
            exit;
        }
    }

    /**
     * Identify suspicious bot accounts
     */
    public static function get_suspicious_users($filter = 'detected') {
        $users = get_users([
            'role__in' => ['subscriber', 'customer'],
            'orderby'  => 'user_registered',
            'order'    => 'DESC',
            'number'   => 300,
        ]);

        $list = [];

        $verified_human_ids = [1, 48, 121, 128, 129, 130];

        foreach ($users as $u) {
            // Never ever touch administrator or instructors
            if ($u->ID === 1 || in_array('administrator', (array)$u->roles, true) || in_array('tutor_instructor', (array)$u->roles, true)) {
                continue;
            }

            // Explicitly verified human accounts
            $is_verified = in_array($u->ID, $verified_human_ids, true);
            if ($is_verified && $filter !== 'all') {
                continue;
            }

            $reasons = [];
            $email = strtolower($u->user_email);
            $login = $u->user_login;

            if (!$is_verified) {
                // Check email domain
                if (strpos($email, '@example.') !== false || strpos($email, '@formtests.info') !== false) {
                    $reasons[] = 'بريد وهمي تجريبي (@example / formtests)';
                }

                // Dot-stuffing attack in email: e.g. e.duc.ak.oc966
                $local = strstr($email, '@', true);
                if ($local && substr_count($local, '.') >= 3) {
                    $reasons[] = 'نمط نقاط متكررة لتوليد بريد آلي (Dot Stuffing)';
                }

                // True gibberish: 5+ consecutive consonants (e.g. drhjfpkohi, skmfhlokik)
                if (preg_match('/[bcdfghjklmnpqrstvwxyz]{5,}/i', $login)) {
                    $reasons[] = 'اسم مستخدم عشوائي مولّد آلياً (تتالي أحرف ساكنة)';
                }

                // Mixed uppercase-lowercase long bot strings: e.g. NgsJJtNaWnOBRUhNoKmJRAL
                if (preg_match('/[a-z]{2,}[A-Z]{2,}/', $login) && strlen($login) > 12) {
                    $reasons[] = 'اسم مستخدم عشوائي بنمط آلي مختلط';
                }

                // Pattern firstname.lastname<digits> e.g. emma.smith25102
                if (preg_match('/^[a-z]+\.[a-z]+[0-9]{4,6}$/i', $login)) {
                    $reasons[] = 'نمط بوت وهمي لتوليد أسماء مركبة وأرقام عشوائية';
                }

                // October 2026 bot wave spike check
                if (strpos($u->user_registered, '2026-10-') === 0 && !empty($reasons)) {
                    $reasons[] = 'ضمن موجة هجمات أكتوبر 2026';
                }
            } else {
                $reasons[] = 'حساب موثق (إنسان حقيقي)';
            }

            $is_suspicious = !empty($reasons) && !$is_verified;

            if ($filter === 'all' || $is_suspicious) {
                $list[] = [
                    'id'            => $u->ID,
                    'login'         => $u->user_login,
                    'email'         => $u->user_email,
                    'registered'    => $u->user_registered,
                    'roles'         => implode(', ', (array)$u->roles),
                    'reasons'       => $reasons,
                    'is_suspicious' => $is_suspicious,
                ];
            }
        }

        return $list;
    }

    public static function render_admin_dashboard() {
        $tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'overview';
        $view_mode = isset($_GET['view']) && $_GET['view'] === 'all' ? 'all' : 'detected';
        $stats = Etadrib_Guard_Logger::get_stats();
        $settings = Etadrib_Guard_Core::get_settings();
        $suspicious_users = self::get_suspicious_users($view_mode);
        $total_threats = ($stats['total_blocked_regs'] ?? 0) + ($stats['total_blocked_logins'] ?? 0) + ($stats['total_blocked_xmlrpc'] ?? 0) + ($stats['total_blocked_other'] ?? 0);

        ?>
        <div class="wrap et-guard-admin-wrap" dir="rtl" style="text-align: right; font-family: system-ui, -apple-system, sans-serif;">
            
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); color: #fff; padding: 24px 30px; border-radius: 12px; margin: 20px 0 25px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 15px;">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span class="dashicons dashicons-shield-alt" style="font-size: 42px; width: 42px; height: 42px; color: #38bdf8;"></span>
                        <div>
                            <h1 style="color: #fff; margin: 0; font-size: 24px; font-weight: 700;">حارس إتدريب - درع الحماية ضد البوتات والتسجيل الوهمي</h1>
                            <p style="color: #94a3b8; margin: 5px 0 0; font-size: 14px;">نظام مهندس لحظر هجمات الروبوتات وحصر تسجيل الدخول وإنشاء الحسابات للبشر الحقيقيين فقط.</p>
                        </div>
                    </div>
                    <div>
                        <span style="display: inline-flex; align-items: center; gap: 6px; background: rgba(16, 185, 129, 0.2); color: #34d399; padding: 8px 16px; border-radius: 9999px; font-weight: 600; font-size: 13px; border: 1px solid rgba(16, 185, 129, 0.4);">
                            <span style="width: 8px; height: 8px; background: #10b981; border-radius: 50%; display: inline-block;"></span>
                            نظام الحماية الذكي: نَشِط وفعّال
                        </span>
                    </div>
                </div>
            </div>

            <!-- Messages -->
            <?php if (isset($_GET['updated'])): ?>
                <div class="notice notice-success is-dismissible" style="padding: 12px; border-radius: 6px;"><p><strong>تم حفظ الإعدادات بنجاح.</strong></p></div>
            <?php elseif (isset($_GET['cleared'])): ?>
                <div class="notice notice-success is-dismissible" style="padding: 12px; border-radius: 6px;"><p><strong>تم مسح سجل الهجمات بالكامل.</strong></p></div>
            <?php elseif (isset($_GET['deleted'])): ?>
                <div class="notice notice-success is-dismissible" style="padding: 12px; border-radius: 6px;"><p><strong>تم حذف <?php echo intval($_GET['deleted']); ?> حساب وهمي بنجاح وأمان.</strong></p></div>
            <?php endif; ?>

            <!-- Navigation Tabs -->
            <h2 class="nav-tab-wrapper" style="margin-bottom: 25px; border-bottom: 2px solid #cbd5e1;">
                <a href="<?php echo esc_url(add_query_arg(['page' => 'etadrib-human-guard', 'tab' => 'overview'], admin_url('admin.php'))); ?>" class="nav-tab <?php echo $tab === 'overview' ? 'nav-tab-active' : ''; ?>" style="font-weight: 600; font-size: 15px; padding: 8px 18px;">
                    <span class="dashicons dashicons-dashboard" style="vertical-align: middle; margin-left: 5px;"></span> نظرة عامة
                </a>
                <a href="<?php echo esc_url(add_query_arg(['page' => 'etadrib-human-guard', 'tab' => 'cleanup'], admin_url('admin.php'))); ?>" class="nav-tab <?php echo $tab === 'cleanup' ? 'nav-tab-active' : ''; ?>" style="font-weight: 600; font-size: 15px; padding: 8px 18px;">
                    <span class="dashicons dashicons-trash" style="vertical-align: middle; margin-left: 5px;"></span> تنظيف الحسابات الوهمية (<?php echo count($suspicious_users); ?>)
                </a>
                <a href="<?php echo esc_url(add_query_arg(['page' => 'etadrib-human-guard', 'tab' => 'logs'], admin_url('admin.php'))); ?>" class="nav-tab <?php echo $tab === 'logs' ? 'nav-tab-active' : ''; ?>" style="font-weight: 600; font-size: 15px; padding: 8px 18px;">
                    <span class="dashicons dashicons-list-view" style="vertical-align: middle; margin-left: 5px;"></span> سجل الهجمات المحظورة
                </a>
                <a href="<?php echo esc_url(add_query_arg(['page' => 'etadrib-human-guard', 'tab' => 'settings'], admin_url('admin.php'))); ?>" class="nav-tab <?php echo $tab === 'settings' ? 'nav-tab-active' : ''; ?>" style="font-weight: 600; font-size: 15px; padding: 8px 18px;">
                    <span class="dashicons dashicons-admin-settings" style="vertical-align: middle; margin-left: 5px;"></span> إعدادات الأمان
                </a>
            </h2>

            <!-- TAB 1: OVERVIEW -->
            <?php if ($tab === 'overview'): ?>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px;">
                    
                    <div style="background: #fff; padding: 22px; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 13px; font-weight: 600; color: #64748b;">إجمالي الهجمات المحظورة</span>
                            <span class="dashicons dashicons-shield" style="color: #0284c7; font-size: 24px;"></span>
                        </div>
                        <div style="font-size: 32px; font-weight: 700; color: #0f172a; margin: 10px 0 0;"><?php echo number_format($total_threats); ?></div>
                    </div>

                    <div style="background: #fff; padding: 22px; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 13px; font-weight: 600; color: #64748b;">تسجيلات بوتات محظورة</span>
                            <span class="dashicons dashicons-dismiss" style="color: #ef4444; font-size: 24px;"></span>
                        </div>
                        <div style="font-size: 32px; font-weight: 700; color: #ef4444; margin: 10px 0 0;"><?php echo number_format($stats['total_blocked_regs'] ?? 0); ?></div>
                    </div>

                    <div style="background: #fff; padding: 22px; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 13px; font-weight: 600; color: #64748b;">محاولات تخمين الدخول (Brute-Force)</span>
                            <span class="dashicons dashicons-lock" style="color: #f59e0b; font-size: 24px;"></span>
                        </div>
                        <div style="font-size: 32px; font-weight: 700; color: #f59e0b; margin: 10px 0 0;"><?php echo number_format($stats['total_blocked_logins'] ?? 0); ?></div>
                    </div>

                    <div style="background: #fff; padding: 22px; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 13px; font-weight: 600; color: #64748b;">طلبات XML-RPC المحظورة</span>
                            <span class="dashicons dashicons-networking" style="color: #8b5cf6; font-size: 24px;"></span>
                        </div>
                        <div style="font-size: 32px; font-weight: 700; color: #8b5cf6; margin: 10px 0 0;"><?php echo number_format($stats['total_blocked_xmlrpc'] ?? 0); ?></div>
                    </div>

                </div>

                <!-- Active Protection Layers Grid -->
                <div style="background: #fff; padding: 28px; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 30px;">
                    <h3 style="margin-top: 0; font-size: 18px; font-weight: 700; color: #1e293b; border-bottom: 1px solid #f1f5f9; padding-bottom: 12px;">
                        طبقات الحماية النشطة على موقع etadrib.com
                    </h3>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; margin-top: 20px;">
                        
                        <div style="padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc;">
                            <div style="font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 8px;">
                                <span class="dashicons dashicons-yes-alt" style="color: #10b981;"></span>
                                مصيدة الحقول المخفية (Invisible Honeypot)
                            </div>
                            <p style="margin: 6px 0 0; font-size: 13px; color: #64748b;">تستدرج برامج السبام الآلية لتعبئة حقول مخفية عن البشر، ويتم رفض الطلب فورا بصمت.</p>
                        </div>

                        <div style="padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc;">
                            <div style="font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 8px;">
                                <span class="dashicons dashicons-yes-alt" style="color: #10b981;"></span>
                                قيد التوقيت البشري (Submission Time Trap)
                            </div>
                            <p style="margin: 6px 0 0; font-size: 13px; color: #64748b;">يحظر إرسال النماذج فائق السرعة عبر السكربتات (أقل من ثانيتين) مع توقيع أمني مشفر.</p>
                        </div>

                        <div style="padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc;">
                            <div style="font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 8px;">
                                <span class="dashicons dashicons-yes-alt" style="color: #10b981;"></span>
                                إثبات المتصفح الحقيقي (JavaScript Proof)
                            </div>
                            <p style="margin: 6px 0 0; font-size: 13px; color: #64748b;">يتطلب تنفيذاً برمجياً حقيقياً داخل المتصفح، مما يُعطّل أدوات curl و python والأجهزة الوهمية.</p>
                        </div>

                        <div style="padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc;">
                            <div style="font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 8px;">
                                <span class="dashicons dashicons-yes-alt" style="color: #10b981;"></span>
                                التحقق البشري التفاعلي (Math Challenge)
                            </div>
                            <p style="margin: 6px 0 0; font-size: 13px; color: #64748b;">سؤال رياضي سريع وبسيط للبشر (مثل 4+3) مستحيل على برامج التسجيل الآلية حله.</p>
                        </div>

                        <div style="padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc;">
                            <div style="font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 8px;">
                                <span class="dashicons dashicons-yes-alt" style="color: #10b981;"></span>
                                حظر الإيميلات المؤقتة وأنماط الروبوتات
                            </div>
                            <p style="margin: 6px 0 0; font-size: 13px; color: #64748b;">حظر فوري لإيميلات @example.* و نطاقات البريد المؤقت والأنماط المفخخة بنقاط مكررة.</p>
                        </div>

                        <div style="padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc;">
                            <div style="font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 8px;">
                                <span class="dashicons dashicons-yes-alt" style="color: #10b981;"></span>
                                إغلاق ثغرة XML-RPC بالكامل
                            </div>
                            <p style="margin: 6px 0 0; font-size: 13px; color: #64748b;">إيقاف آلاف الهجمات المتكررة على xmlrpc.php وتخفيف الحمل على معالج وخوادم CyberPanel.</p>
                        </div>

                    </div>
                </div>

            <!-- TAB 2: CLEANUP SUSPICIOUS USERS -->
            <?php elseif ($tab === 'cleanup'): ?>
                <div style="background: #fff; padding: 25px; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; margin-bottom: 20px;">
                        <div>
                            <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: #1e293b;">
                                فحص وتنظيف الحسابات الوهمية المسجلة
                            </h3>
                            <p style="color: #64748b; margin: 5px 0 0; font-size: 13px;">
                                تم فحص قاعدة البيانات وتحديد الحسابات التي تحمل بصمات التسجيل الآلي (أسماء عشوائية، إيميلات وهمية، تواريخ الهجمات).
                            </p>
                        </div>
                        <div style="display: flex; gap: 8px;">
                            <a href="<?php echo esc_url(add_query_arg(['page' => 'etadrib-human-guard', 'tab' => 'cleanup', 'view' => 'detected'], admin_url('admin.php'))); ?>" class="button <?php echo $view_mode !== 'all' ? 'button-primary' : ''; ?>">
                                البوتات المكتشفة تلقائياً (<?php echo count(self::get_suspicious_users('detected')); ?>)
                            </a>
                            <a href="<?php echo esc_url(add_query_arg(['page' => 'etadrib-human-guard', 'tab' => 'cleanup', 'view' => 'all'], admin_url('admin.php'))); ?>" class="button <?php echo $view_mode === 'all' ? 'button-primary' : ''; ?>">
                                عرض كافة المشتركين للمراجعة
                            </a>
                        </div>
                    </div>

                    <?php if (empty($suspicious_users)): ?>
                        <div style="text-align: center; padding: 40px; background: #f8fafc; border-radius: 8px; border: 1px dashed #cbd5e1;">
                            <span class="dashicons dashicons-yes-alt" style="font-size: 48px; width: 48px; height: 48px; color: #10b981;"></span>
                            <h4 style="margin: 10px 0 5px; font-size: 16px; color: #1e293b;">قاعدة البيانات نظيفة تماماً!</h4>
                            <p style="color: #64748b; font-size: 13px; margin: 0;">لم يتم العثور على أي حسابات وهمية مشبوهة حالياً.</p>
                        </div>
                    <?php else: ?>
                        <form method="post" id="et-guard-delete-form" onsubmit="return confirm('هل أنت متأكد من رغبتك في حذف الحسابات المحددة نهائياً؟ هذا الإجراء لا يمكن التراجع عنه وسيحذف فقط حسابات البوتات المحددة.');">
                            <?php wp_nonce_field('et_guard_delete_users_nonce', '_et_nonce'); ?>

                            <div style="margin-bottom: 15px; display: flex; gap: 10px; align-items: center;">
                                <button type="button" class="button" onclick="etSelectAllUsers(true);">تحديد الكل (<?php echo count($suspicious_users); ?>)</button>
                                <button type="button" class="button" onclick="etSelectAllUsers(false);">إلغاء التحديد</button>
                                <button type="submit" name="et_guard_bulk_delete_users" class="button button-primary" style="background: #ef4444; border-color: #dc2626; margin-right: auto;">
                                    <span class="dashicons dashicons-trash" style="vertical-align: middle; margin-left: 4px;"></span>
                                    حذف الحسابات المحددة نهائياً
                                </button>
                            </div>

                            <table class="wp-list-table widefat fixed striped table-view-list">
                                <thead>
                                    <tr>
                                        <th style="width: 40px;"><input type="checkbox" id="et-select-all" onclick="etToggleAll(this);" /></th>
                                        <th style="width: 70px;">ID</th>
                                        <th>اسم المستخدم</th>
                                        <th>البريد الإلكتروني</th>
                                        <th>تاريخ التسجيل</th>
                                        <th>الرتبة</th>
                                        <th>أسباب الاشتباه (بصمة البوت)</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($suspicious_users as $su): ?>
                                        <tr>
                                            <td><input type="checkbox" name="selected_users[]" value="<?php echo esc_attr($su['id']); ?>" class="et-user-chk" checked /></td>
                                            <td><strong>#<?php echo esc_html($su['id']); ?></strong></td>
                                            <td><code style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px;"><?php echo esc_html($su['login']); ?></code></td>
                                            <td><?php echo esc_html($su['email']); ?></td>
                                            <td><?php echo esc_html($su['registered']); ?></td>
                                            <td><span class="badge" style="background: #e2e8f0; padding: 3px 8px; border-radius: 4px; font-size: 11px;"><?php echo esc_html($su['roles']); ?></span></td>
                                            <td>
                                                <?php foreach ($su['reasons'] as $r): ?>
                                                    <span style="display: inline-block; background: #fee2e2; color: #991b1b; padding: 2px 7px; border-radius: 4px; font-size: 11px; margin: 1px 2px;">
                                                        <?php echo esc_html($r); ?>
                                                    </span>
                                                <?php endforeach; ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </form>

                        <script>
                        function etToggleAll(master) {
                            var chks = document.querySelectorAll('.et-user-chk');
                            for (var i = 0; i < chks.length; i++) {
                                chks[i].checked = master.checked;
                            }
                        }
                        function etSelectAllUsers(val) {
                            var chks = document.querySelectorAll('.et-user-chk');
                            for (var i = 0; i < chks.length; i++) {
                                chks[i].checked = val;
                            }
                            document.getElementById('et-select-all').checked = val;
                        }
                        </script>
                    <?php endif; ?>
                </div>

            <!-- TAB 3: ATTACK LOGS -->
            <?php elseif ($tab === 'logs'): ?>
                <div style="background: #fff; padding: 25px; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px;">
                        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: #1e293b;">
                            سجل الهجمات والعمليات الآلية المحظورة
                        </h3>
                        <form method="post" onsubmit="return confirm('هل تريد بالتأكيد مسح كافة السجلات؟');">
                            <?php wp_nonce_field('et_guard_clear_logs_nonce', '_et_nonce'); ?>
                            <button type="submit" name="et_guard_clear_logs" class="button">مسح السجل</button>
                        </form>
                    </div>

                    <?php
                    $logs = Etadrib_Guard_Logger::get_recent_logs(80);
                    if (empty($logs)):
                    ?>
                        <p style="text-align: center; color: #64748b; padding: 40px; background: #f8fafc; border-radius: 8px;">لا توجد هجمات مسجلة بعد. النظام يراقب باستمرار.</p>
                    <?php else: ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th style="width: 140px;">التوقيت</th>
                                    <th style="width: 120px;">IP المهاجم</th>
                                    <th style="width: 100px;">النوع</th>
                                    <th style="width: 170px;">سبب الحظر</th>
                                    <th>المعرف / البريد المستهدف</th>
                                    <th style="width: 250px;">User Agent</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($logs as $l): ?>
                                    <tr>
                                        <td><?php echo esc_html($l['created_at']); ?></td>
                                        <td><code><?php echo esc_html($l['ip_address']); ?></code></td>
                                        <td>
                                            <?php if ($l['event_type'] === 'registration'): ?>
                                                <span style="color: #ef4444; font-weight: bold;">تسجيل حساب</span>
                                            <?php elseif ($l['event_type'] === 'login'): ?>
                                                <span style="color: #f59e0b; font-weight: bold;">تسجيل دخول</span>
                                            <?php elseif ($l['event_type'] === 'xmlrpc'): ?>
                                                <span style="color: #8b5cf6; font-weight: bold;">XML-RPC</span>
                                            <?php else: ?>
                                                <span><?php echo esc_html($l['event_type']); ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <td><span style="background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 4px; font-size: 11px;"><?php echo esc_html($l['block_reason']); ?></span></td>
                                        <td><code><?php echo esc_html($l['user_identifier'] ?: '-'); ?></code></td>
                                        <td style="font-size: 11px; color: #64748b; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"><?php echo esc_html($l['user_agent']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>

            <!-- TAB 4: SETTINGS -->
            <?php elseif ($tab === 'settings'): ?>
                <div style="background: #fff; padding: 25px; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05); max-width: 800px;">
                    <h3 style="margin-top: 0; font-size: 18px; font-weight: 700; color: #1e293b; border-bottom: 1px solid #f1f5f9; padding-bottom: 12px;">
                        إعدادات أمان التسجيل والدخول
                    </h3>

                    <form method="post">
                        <?php wp_nonce_field('et_guard_settings_nonce', '_et_nonce'); ?>

                        <table class="form-table">
                            <tr>
                                <th scope="row">مصيدة الحقول المخفية (Honeypot)</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="honeypot_enabled" value="1" <?php checked(1, $settings['honeypot_enabled']); ?> />
                                        تفعيل مصيدة الحقول المخفية (توقع الروبوتات في حقول سرية وترفض طلبها فوراً).
                                    </label>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">قيد التوقيت البشري (Time Trap)</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="time_trap_enabled" value="1" <?php checked(1, $settings['time_trap_enabled']); ?> />
                                        تفعيل فحص سرعة الإرسال لمنع الإرسال الفوري للسكربتات.
                                    </label>
                                    <div style="margin-top: 8px;">
                                        الحد الأدنى لثواني تعبئة النموذج:
                                        <input type="number" name="min_time_seconds" value="<?php echo intval($settings['min_time_seconds']); ?>" min="1" max="10" style="width: 70px;" /> ثواني.
                                    </div>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">إثبات المتصفح الحقيقي (JavaScript Proof)</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="js_token_enabled" value="1" <?php checked(1, $settings['js_token_enabled']); ?> />
                                        توليد رمز أمني ديناميكي عبر كود جافاسكريبت داخل المتصفح (يحظر أي طلب curl / bot مباشر).
                                    </label>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">التحقق الرياضي البشري (Math Challenge)</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="math_challenge_enabled" value="1" <?php checked(1, $settings['math_challenge_enabled']); ?> />
                                        تفعيل سؤال التحقق البشري الذكي (سؤال جمع عشوائي بسيط في نموذج التسجيل).
                                    </label>
                                    <div style="margin-top: 6px;">
                                        <label>
                                            <input type="checkbox" name="math_for_login" value="1" <?php checked(1, $settings['math_for_login']); ?> />
                                            إظهار السؤال دائماً في شاشة تسجيل الدخول (اختياري، يظهر تلقائياً بعد أول محاولة فاشلة).
                                        </label>
                                    </div>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">حظر الإيميلات المؤقتة والوهمية</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="block_disposable_emails" value="1" <?php checked(1, $settings['block_disposable_emails']); ?> />
                                        حظر فوري لإيميلات @example.* ومزودي البريد المؤقت وأنماط تكرار النقاط الآلية.
                                    </label>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">حماية معدل الطلبات (Rate Limiting)</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="rate_limit_registrations" value="1" <?php checked(1, $settings['rate_limit_registrations']); ?> />
                                        تحديد محاولات التسجيل (بحد أقصى 3 محاولات لكل عنوان IP خلال 30 دقيقة).
                                    </label>
                                    <div style="margin-top: 6px;">
                                        <label>
                                            <input type="checkbox" name="rate_limit_logins" value="1" <?php checked(1, $settings['rate_limit_logins']); ?> />
                                            حظر عنوان IP مؤقتاً لمدة 15 دقيقة بعد 5 محاولات دخول فاشلة متتالية (Brute-Force Lockout).
                                        </label>
                                    </div>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">حظر XML-RPC نهائياً</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="block_xmlrpc" value="1" <?php checked(1, $settings['block_xmlrpc']); ?> />
                                        إغلاق منفذ xmlrpc.php نهائياً (يوقف هجمات الحرمان من الخدمة والتخمين المستمر).
                                    </label>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row">Cloudflare Turnstile (اختياري)</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="turnstile_enabled" value="1" <?php checked(1, $settings['turnstile_enabled']); ?> />
                                        استخدام خدمة Cloudflare Turnstile كطبقة تحقق إضافية (إذا كنت تملك مفاتيح API).
                                    </label>
                                    <div style="margin-top: 8px;">
                                        Site Key: <input type="text" name="turnstile_site_key" value="<?php echo esc_attr($settings['turnstile_site_key']); ?>" class="regular-text" /><br />
                                        Secret Key: <input type="password" name="turnstile_secret_key" value="<?php echo esc_attr($settings['turnstile_secret_key']); ?>" class="regular-text" style="margin-top: 5px;" />
                                    </div>
                                </td>
                            </tr>
                        </table>

                        <p class="submit" style="margin-top: 25px;">
                            <button type="submit" name="et_guard_save_settings" class="button button-primary button-large">حفظ الإعدادات</button>
                        </p>
                    </form>
                </div>
            <?php endif; ?>

        </div>
        <?php
    }
}
