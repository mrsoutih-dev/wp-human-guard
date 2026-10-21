<?php
if (!defined('ABSPATH')) {
    exit;
}

class Human_Guard_Core {

    const OPTION_SETTINGS = 'human_guard_settings';

    private static $default_settings = [
        'honeypot_enabled'         => 1,
        'time_trap_enabled'        => 1,
        'min_time_seconds'         => 2,     // humans need >= 2 seconds to interact
        'js_token_enabled'         => 1,
        'math_challenge_enabled'   => 1,     // interactive human math challenge
        'math_for_login'           => 0,     // keep login streamlined, trigger math after 1 failed login
        'block_disposable_emails'  => 1,
        'rate_limit_registrations' => 1,     // max 3 registrations per IP per 30 minutes
        'rate_limit_logins'        => 1,     // max 5 failed logins per IP per 15 minutes
        'block_xmlrpc'             => 1,     // block xmlrpc attacks completely
        'turnstile_enabled'        => 0,
        'turnstile_site_key'       => '',
        'turnstile_secret_key'     => '',
    ];

    public static function get_settings() {
        $saved = get_option(self::OPTION_SETTINGS, []);
        return wp_parse_args($saved, self::$default_settings);
    }

    public static function update_settings($new_settings) {
        $current = self::get_settings();
        $updated = array_merge($current, $new_settings);
        return update_option(self::OPTION_SETTINGS, $updated);
    }

    private static function get_secret() {
        return defined('NONCE_KEY') ? NONCE_KEY : (defined('AUTH_KEY') ? AUTH_KEY : 'humanguard_secret_salt_#9901!');
    }

    /**
     * Generate dynamic JS verification seed
     */
    public static function get_js_expected_token($seed) {
        return hash_hmac('sha256', $seed . '_humanguard_verified', self::get_secret());
    }

    /**
     * Render anti-bot fields for forms (Registration / Login)
     */
    public static function render_form_fields($form_type = 'registration') {
        $settings = self::get_settings();
        $now = time();
        $client_ip = Human_Guard_Logger::get_client_ip();
        $time_signature = hash_hmac('sha256', $now . '|' . $client_ip, self::get_secret());
        $js_seed = wp_generate_password(12, false);
        $js_expected = self::get_js_expected_token($js_seed);

        echo "\n<!-- HumanGuard Security Layer by zohodigital.com -->\n";

        // 1. Invisible Honeypot Trap
        if (!empty($settings['honeypot_enabled'])) {
            $hp_name_1 = 'hg_user_website_hp';
            $hp_name_2 = 'hg_user_company_hp';
            ?>
            <div class="hg-guard-hp-wrap" style="position:absolute !important; left:-9999px !important; top:-9999px !important; width:1px !important; height:1px !important; overflow:hidden !important; opacity:0 !important; pointer-events:none !important;" aria-hidden="true" tabindex="-1">
                <label for="<?php echo esc_attr($hp_name_1); ?>">Leave this field empty</label>
                <input type="text" name="<?php echo esc_attr($hp_name_1); ?>" id="<?php echo esc_attr($hp_name_1); ?>" value="" autocomplete="off" tabindex="-1" />
                <input type="text" name="<?php echo esc_attr($hp_name_2); ?>" id="<?php echo esc_attr($hp_name_2); ?>" value="" autocomplete="off" tabindex="-1" />
                <!-- Legacy honeypot check for bots that cached previous form fields -->
                <input type="text" name="et_user_website_hp" value="" autocomplete="off" tabindex="-1" />
            </div>
            <?php
        }

        // 2. Time Trap Tokens
        if (!empty($settings['time_trap_enabled'])) {
            echo '<input type="hidden" name="hg_guard_ts" value="' . esc_attr($now) . '" />' . "\n";
            echo '<input type="hidden" name="hg_guard_ts_sig" value="' . esc_attr($time_signature) . '" />' . "\n";
        }

        // 3. Dynamic JS Token Field
        if (!empty($settings['js_token_enabled'])) {
            echo '<input type="hidden" name="hg_guard_js_seed" value="' . esc_attr($js_seed) . '" />' . "\n";
            echo '<input type="hidden" name="hg_guard_js_tok" class="hg-guard-js-token" value="" />' . "\n";
            ?>
            <script>
            (function() {
                try {
                    var s = "<?php echo esc_js($js_seed); ?>";
                    var token = "<?php echo esc_js($js_expected); ?>";
                    function fillGuard() {
                        var inputs = document.querySelectorAll('.hg-guard-js-token');
                        for (var i = 0; i < inputs.length; i++) {
                            inputs[i].value = token;
                        }
                    }
                    if (document.readyState === 'loading') {
                        document.addEventListener('DOMContentLoaded', fillGuard);
                    } else {
                        fillGuard();
                    }
                    window.addEventListener('mousemove', fillGuard, {once: true});
                    window.addEventListener('touchstart', fillGuard, {once: true});
                    window.addEventListener('keydown', fillGuard, {once: true});
                } catch(e) {}
            })();
            </script>
            <?php
        }

        // 4. Cloudflare Turnstile if enabled
        if (!empty($settings['turnstile_enabled']) && !empty($settings['turnstile_site_key'])) {
            echo '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
            echo '<div class="cf-turnstile" data-sitekey="' . esc_attr($settings['turnstile_site_key']) . '" style="margin: 15px 0;"></div>';
            return;
        }

        // 5. Smart Math Challenge
        $show_math = false;
        if ($form_type === 'registration' && !empty($settings['math_challenge_enabled'])) {
            $show_math = true;
        } elseif ($form_type === 'login') {
            if (!empty($settings['math_for_login']) || self::get_ip_failed_login_count($client_ip) > 0) {
                $show_math = true;
            }
        }

        if ($show_math) {
            $num1 = mt_rand(1, 9);
            $num2 = mt_rand(1, 9);
            $answer = $num1 + $num2;
            $math_token = hash_hmac('sha256', $answer . '|' . $now . '|' . $client_ip, self::get_secret());

            ?>
            <div class="hg-guard-math-container" style="margin: 15px 0; padding: 12px 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;">
                <label for="hg_guard_math_ans" style="display: block; font-weight: 600; margin-bottom: 6px; font-size: 14px; color: #1e293b;">
                    <span class="dashicons dashicons-shield" style="font-size: 16px; line-height: 1.4; vertical-align: middle; color: #0284c7;"></span>
                    <span class="hg-guard-q-ar">التحقق البشري: كم حاصل جمع <?php echo intval($num1); ?> + <?php echo intval($num2); ?> ؟</span>
                    <span class="hg-guard-q-en" style="font-size: 12px; color: #64748b; font-weight: normal; margin-left: 5px;">(Human Check: <?php echo intval($num1); ?> + <?php echo intval($num2); ?> = ?)</span>
                </label>
                <input type="number" name="hg_guard_math_ans" id="hg_guard_math_ans" class="input" style="width: 100px; padding: 8px 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 16px; text-align: center;" placeholder="?" required autocomplete="off" />
                <input type="hidden" name="hg_guard_math_token" value="<?php echo esc_attr($math_token); ?>" />
                <input type="hidden" name="hg_guard_math_ts" value="<?php echo esc_attr($now); ?>" />
                <small style="display: block; margin-top: 4px; font-size: 11px; color: #64748b;">
                    لحماية الموقع من التسجيلات الآلية غير المصرح بها - HumanGuard by zohodigital.com
                </small>
            </div>
            <?php
        }
    }

    /**
     * Validate submission for bots
     */
    public static function verify_submission($form_type = 'registration', $user_identifier = '') {
        $settings = self::get_settings();
        $ip = Human_Guard_Logger::get_client_ip();

        // 1. Rate Limiting Check
        if ($form_type === 'registration' && !empty($settings['rate_limit_registrations'])) {
            $reg_key = 'hg_reg_' . md5($ip);
            $reg_count = (int) get_transient($reg_key);
            if ($reg_count >= 3) {
                Human_Guard_Logger::log('registration', 'rate_limit_exceeded', $user_identifier);
                return new WP_Error('hg_rate_limit', 'لقد تجاوزت الحد الأقصى لمحاولات التسجيل من عنوان جهازك. يرجى المحاولة بعد 30 دقيقة.');
            }
        }

        // Login Lockout Check
        if ($form_type === 'login' && !empty($settings['rate_limit_logins'])) {
            $lockout_key = 'hg_lockout_' . md5($ip);
            if (get_transient($lockout_key)) {
                Human_Guard_Logger::log('login', 'ip_locked_out', $user_identifier);
                return new WP_Error('hg_locked_out', 'تم حظر تسجيل الدخول مؤقتاً بسبب تكرار المحاولات الفاشلة. يرجى المحاولة بعد 15 دقيقة.');
            }
        }

        // 2. Invisible Honeypot Trap
        if (!empty($settings['honeypot_enabled'])) {
            if (!empty($_POST['hg_user_website_hp']) || !empty($_POST['hg_user_company_hp']) || !empty($_POST['et_user_website_hp'])) {
                Human_Guard_Logger::log($form_type, 'honeypot_triggered', $user_identifier);
                return new WP_Error('hg_bot_honeypot', 'عذراً، تم رصد نشاط آلي غير مصرح به.');
            }
        }

        // 3. Email Pattern & Disposable Blacklist Check
        if ($form_type === 'registration' && !empty($settings['block_disposable_emails'])) {
            $email = '';
            if (!empty($_POST['user_email'])) {
                $email = sanitize_email(wp_unslash($_POST['user_email']));
            } elseif (!empty($_POST['email'])) {
                $email = sanitize_email(wp_unslash($_POST['email']));
            }

            if (!empty($email)) {
                $email_check = self::is_suspicious_or_blacklisted_email($email);
                if ($email_check !== false) {
                    Human_Guard_Logger::log('registration', 'blacklisted_email: ' . $email_check, $email);
                    return new WP_Error('hg_invalid_email_domain', 'البريد الإلكتروني المدخل غير صالح أو غير مسموح به في الموقع.');
                }
            }
        }

        // 4. Cloudflare Turnstile Verification (if enabled)
        if (!empty($settings['turnstile_enabled']) && !empty($settings['turnstile_secret_key'])) {
            $cf_token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field(wp_unslash($_POST['cf-turnstile-response'])) : '';
            if (empty($cf_token)) {
                Human_Guard_Logger::log($form_type, 'turnstile_missing_token', $user_identifier);
                return new WP_Error('hg_turnstile_missing', 'يرجى إكمال التحقق البشري من Cloudflare.');
            }
            $cf_res = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
                'body' => [
                    'secret'   => $settings['turnstile_secret_key'],
                    'response' => $cf_token,
                    'remoteip' => $ip,
                ],
                'timeout' => 10,
            ]);
            if (!is_wp_error($cf_res)) {
                $cf_data = json_decode(wp_remote_retrieve_body($cf_res), true);
                if (empty($cf_data['success'])) {
                    Human_Guard_Logger::log($form_type, 'turnstile_verification_failed', $user_identifier);
                    return new WP_Error('hg_turnstile_failed', 'فشل التحقق البشري من Cloudflare.');
                }
            }
            return true;
        }

        // 5. Time Trap Check (Speed limit)
        if (!empty($settings['time_trap_enabled'])) {
            $ts = isset($_POST['hg_guard_ts']) ? intval($_POST['hg_guard_ts']) : (isset($_POST['et_guard_ts']) ? intval($_POST['et_guard_ts']) : 0);
            $ts_sig = isset($_POST['hg_guard_ts_sig']) ? sanitize_text_field(wp_unslash($_POST['hg_guard_ts_sig'])) : (isset($_POST['et_guard_ts_sig']) ? sanitize_text_field(wp_unslash($_POST['et_guard_ts_sig'])) : '');

            if (empty($ts) || empty($ts_sig)) {
                Human_Guard_Logger::log($form_type, 'missing_time_token', $user_identifier);
                return new WP_Error('hg_bot_timing', 'فشل التحقق من أمان النموذج (رمز التوقيت مفقود).');
            }

            // Verify signature
            $expected_sig = hash_hmac('sha256', $ts . '|' . $ip, self::get_secret());
            if (!hash_equals($expected_sig, $ts_sig)) {
                Human_Guard_Logger::log($form_type, 'invalid_time_signature', $user_identifier);
                return new WP_Error('hg_bot_timing', 'فشل التحقق من صحة النموذج.');
            }

            $elapsed = time() - $ts;
            $min_time = isset($settings['min_time_seconds']) ? intval($settings['min_time_seconds']) : 2;
            if ($elapsed < $min_time) {
                Human_Guard_Logger::log($form_type, "time_too_fast_{$elapsed}s", $user_identifier);
                return new WP_Error('hg_bot_speed', 'تم إرسال النموذج بسرعة غير طبيعية (روبوت آلي).');
            }

            if ($elapsed > 7200) {
                Human_Guard_Logger::log($form_type, 'time_expired', $user_identifier);
                return new WP_Error('hg_bot_expired', 'انتهت صلاحية جلسة النموذج. يرجى تحديث الصفحة والمحاولة مجدداً.');
            }
        }

        // 6. Dynamic JS Token Check
        if (!empty($settings['js_token_enabled'])) {
            $seed = isset($_POST['hg_guard_js_seed']) ? sanitize_text_field(wp_unslash($_POST['hg_guard_js_seed'])) : '';
            $token = isset($_POST['hg_guard_js_tok']) ? sanitize_text_field(wp_unslash($_POST['hg_guard_js_tok'])) : '';

            if (empty($seed) || empty($token)) {
                Human_Guard_Logger::log($form_type, 'missing_js_token', $user_identifier);
                return new WP_Error('hg_bot_js', 'يتطلب الموقع متصفحاً حقيقياً يدعم الجافاسكريبت لحماية الحسابات.');
            }

            $expected_token = self::get_js_expected_token($seed);
            if (!hash_equals($expected_token, $token)) {
                Human_Guard_Logger::log($form_type, 'invalid_js_token', $user_identifier);
                return new WP_Error('hg_bot_js', 'فشل رمز التحقق الأمني من المتصفح.');
            }
        }

        // 7. Math Challenge Check
        $math_token = isset($_POST['hg_guard_math_token']) ? sanitize_text_field(wp_unslash($_POST['hg_guard_math_token'])) : '';
        $math_ts = isset($_POST['hg_guard_math_ts']) ? intval($_POST['hg_guard_math_ts']) : 0;
        $math_ans = isset($_POST['hg_guard_math_ans']) ? trim(sanitize_text_field(wp_unslash($_POST['hg_guard_math_ans']))) : '';

        if (!empty($math_token) || ($form_type === 'registration' && !empty($settings['math_challenge_enabled']))) {
            if ($math_ans === '' || empty($math_token) || empty($math_ts)) {
                Human_Guard_Logger::log($form_type, 'math_challenge_empty', $user_identifier);
                return new WP_Error('hg_math_empty', 'يرجى الإجابة على سؤال التحقق البشري للمتابعة.');
            }

            $expected_math = hash_hmac('sha256', intval($math_ans) . '|' . $math_ts . '|' . $ip, self::get_secret());
            if (!hash_equals($expected_math, $math_token)) {
                Human_Guard_Logger::log($form_type, 'math_challenge_wrong_answer', $user_identifier);
                return new WP_Error('hg_math_wrong', 'إجابة التحقق البشري غير صحيحة. يرجى المحاولة مجدداً.');
            }
        }

        // Passed all checks!
        if ($form_type === 'registration' && !empty($settings['rate_limit_registrations'])) {
            $reg_key = 'hg_reg_' . md5($ip);
            $reg_count = (int) get_transient($reg_key);
            set_transient($reg_key, $reg_count + 1, 30 * MINUTE_IN_SECONDS);
        }

        return true;
    }

    /**
     * Check if email domain or pattern is suspicious / spam
     */
    public static function is_suspicious_or_blacklisted_email($email) {
        $email = strtolower(trim($email));
        $parts = explode('@', $email);
        if (count($parts) !== 2) {
            return 'invalid_structure';
        }

        $local = $parts[0];
        $domain = $parts[1];

        $blocked_domains = [
            'example.com', 'example.org', 'example.net', 'formtests.info',
            'mailinator.com', 'guerrillamail.com', 'tempmail.com', '10minutemail.com',
            'sharklasers.com', 'throwawaymail.com', 'yopmail.com', 'fake.com',
            'trashmail.com', 'dispostable.com', 'getairmail.com', 'nada.ltd',
            'mohmal.com', 'crazymailing.com', 'temp-mail.org', 'dropmail.me'
        ];

        if (in_array($domain, $blocked_domains, true)) {
            return "blocked_domain: $domain";
        }

        if (substr_count($local, '.') >= 4) {
            return 'dot_stuffing_bot_pattern';
        }

        return false;
    }

    /**
     * Failed login handling for brute force protection
     */
    public static function record_failed_login($username = '') {
        $settings = self::get_settings();
        if (empty($settings['rate_limit_logins'])) {
            return;
        }

        $ip = Human_Guard_Logger::get_client_ip();
        $fail_key = 'hg_fail_login_' . md5($ip);
        $attempts = (int) get_transient($fail_key) + 1;
        set_transient($fail_key, $attempts, 15 * MINUTE_IN_SECONDS);

        if ($attempts >= 5) {
            $lockout_key = 'hg_lockout_' . md5($ip);
            set_transient($lockout_key, 1, 15 * MINUTE_IN_SECONDS);
            Human_Guard_Logger::log('login', 'ip_locked_out_after_5_failures', $username);
        }
    }

    public static function clear_failed_logins() {
        $ip = Human_Guard_Logger::get_client_ip();
        delete_transient('hg_fail_login_' . md5($ip));
        delete_transient('hg_lockout_' . md5($ip));
    }

    public static function get_ip_failed_login_count($ip) {
        $fail_key = 'hg_fail_login_' . md5($ip);
        return (int) get_transient($fail_key);
    }
}
