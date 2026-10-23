<?php
if (!defined('ABSPATH')) {
    exit;
}

class Human_Guard_Contact {

    public static function init() {
        $settings = Human_Guard_Core::get_settings();

        if (empty($settings['contact_form_protect'])) {
            return;
        }

        // 1. Direct POST interception on early init
        add_action('init', [__CLASS__, 'block_unauthenticated_post_requests'], 1);

        // 2. REST API endpoint protection
        add_filter('rest_pre_dispatch', [__CLASS__, 'protect_rest_endpoints'], 10, 3);

        // 3. Shortcode and Elementor form rendering filter
        add_filter('wpcf7_form_elements', [__CLASS__, 'filter_form_html']);
        add_filter('do_shortcode_tag', [__CLASS__, 'filter_shortcode_output'], 10, 4);

        // 4. Pre-fill & lock contact form fields for logged-in users
        add_filter('wpcf7_form_tag', [__CLASS__, 'prefill_user_data'], 10, 1);

        // 5. Server-side validation and sender verification
        add_filter('wpcf7_validate', [__CLASS__, 'validate_submission'], 10, 2);
        add_filter('wpcf7_posted_data', [__CLASS__, 'enforce_authenticated_user_identity']);

        // 6. Hard safety net before sending email
        add_action('wpcf7_before_send_mail', [__CLASS__, 'verify_before_send_mail'], 10, 2);
    }

    /**
     * Intercept direct POST submissions targeting CF7 from guests/bots.
     */
    public static function block_unauthenticated_post_requests() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['_wpcf7'])) {
            $settings = Human_Guard_Core::get_settings();
            if (!empty($settings['contact_form_auth_only']) && !is_user_logged_in()) {
                $email = sanitize_email($_POST['your-email'] ?? '');
                Human_Guard_Logger::log('contact_form', 'direct_post_unauthenticated_blocked', $email ?: 'guest_bot');

                status_header(403);
                $login_url = home_url('/login/');
                wp_die(
                    '<div dir="rtl" style="font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; text-align: right; max-width: 600px; margin: 40px auto; padding: 25px; border: 1px solid #e2e8f0; border-radius: 8px; background: #fff;">' .
                    '<h2 style="color: #b91c1c; margin-top: 0;">غير مصرح بالوصول (403 Forbidden)</h2>' .
                    '<p style="font-size: 16px; color: #334155; line-height: 1.6;">عذراً، إرسال الرسائل عبر الموقع متاح حصرياً للأعضاء المسجلين والمعتمدين في منصة إتدريب.</p>' .
                    '<p style="margin-top: 20px;"><a href="' . esc_url($login_url) . '" style="display: inline-block; background: #0d6efd; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: 600;">تسجيل الدخول / Log In</a></p>' .
                    '</div>',
                    'غير مصرح به (403 Forbidden)',
                    ['response' => 403, 'back_link' => true]
                );
            }
        }
    }

    /**
     * Block unauthenticated REST API feedback submissions.
     */
    public static function protect_rest_endpoints($result, $server, $request) {
        $route = $request->get_route();
        if (strpos($route, '/contact-form-7/') !== false && strpos($route, '/feedback') !== false) {
            $settings = Human_Guard_Core::get_settings();
            if (!empty($settings['contact_form_auth_only']) && !is_user_logged_in()) {
                Human_Guard_Logger::log('contact_form', 'rest_api_unauthenticated_blocked', 'rest_client');

                return new WP_REST_Response([
                    'code'    => 'humanguard_auth_required',
                    'message' => 'عذراً، إرسال الرسائل متاح فقط للأعضاء المسجلين والمعتمدين في منصة إتدريب.',
                    'data'    => ['status' => 403],
                ], 403);
            }
        }
        return $result;
    }

    /**
     * Replace CF7 form elements with friendly login notice if user is guest.
     */
    public static function filter_form_html($elements) {
        $settings = Human_Guard_Core::get_settings();
        if (!empty($settings['contact_form_auth_only']) && !is_user_logged_in()) {
            return self::render_login_required_notice();
        }
        return $elements;
    }

    /**
     * Filter CF7 shortcode output.
     */
    public static function filter_shortcode_output($output, $tag, $attr, $m) {
        if (in_array($tag, ['contact-form-7', 'contact-form'], true)) {
            $settings = Human_Guard_Core::get_settings();
            if (!empty($settings['contact_form_auth_only']) && !is_user_logged_in()) {
                return self::render_login_required_notice();
            }
        }
        return $output;
    }

    /**
     * HTML template for the login required notice.
     */
    public static function render_login_required_notice() {
        $login_url = home_url('/login/');

        return '
        <div class="humanguard-auth-contact-box" dir="rtl" style="
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 35px 25px;
            text-align: center;
            max-width: 600px;
            margin: 25px auto;
            font-family: inherit;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        ">
            <div style="width: 58px; height: 58px; border-radius: 50%; background: #e0f2fe; color: #0284c7; margin: 0 auto 16px; display: flex; align-items: center; justify-content: center; font-size: 26px;">
                <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:middle;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            </div>
            <h3 style="margin: 0 0 10px; color: #0f172a; font-size: 21px; font-weight: 700;">التواصل متاح للأعضاء المعتمدين فقط</h3>
            <p style="margin: 0 0 22px; color: #64748b; font-size: 15px; line-height: 1.6;">
                للحفاظ على جودة وأمان الخدمة، نموذج المراسلة متاح حصرياً للأعضاء المسجلين والمعتمدين في منصة <strong>إتدريب</strong>.
            </p>
            <a href="' . esc_url($login_url) . '" style="
                display: inline-block;
                background: #0d6efd;
                color: #ffffff !important;
                text-decoration: none;
                padding: 12px 28px;
                border-radius: 8px;
                font-weight: 600;
                font-size: 15px;
                box-shadow: 0 2px 4px rgba(13, 110, 253, 0.2);
            ">تسجيل الدخول / Log In</a>
        </div>';
    }

    /**
     * Pre-populate user name and email from authenticated session and lock them.
     */
    public static function prefill_user_data($tag) {
        if (!is_user_logged_in()) {
            return $tag;
        }

        $current_user = wp_get_current_user();

        if ($tag['name'] === 'your-name' && !empty($current_user->display_name)) {
            $tag['values'] = [(string) $current_user->display_name];
            $tag['options'][] = 'readonly';
        }

        if ($tag['name'] === 'your-email' && !empty($current_user->user_email)) {
            $tag['values'] = [(string) $current_user->user_email];
            $tag['options'][] = 'readonly';
        }

        return $tag;
    }

    /**
     * Invalidate submission if not authenticated.
     */
    public static function validate_submission($result, $tags) {
        $settings = Human_Guard_Core::get_settings();
        if (!empty($settings['contact_form_auth_only']) && !is_user_logged_in()) {
            $result->invalidate('your-message', 'عذراً، إرسال الرسائل متاح حصرياً للأعضاء المسجلين والمعتمدين.');
        }
        return $result;
    }

    /**
     * Force the sender identity in the email payload to match the authenticated user.
     */
    public static function enforce_authenticated_user_identity($posted_data) {
        if (is_user_logged_in()) {
            $current_user = wp_get_current_user();
            if (!empty($current_user->user_email)) {
                $posted_data['your-email'] = $current_user->user_email;
                $posted_data['your-name'] = !empty($current_user->display_name) ? $current_user->display_name : $current_user->user_login;
            }
        }
        return $posted_data;
    }

    /**
     * Hard safety check right before sending mail.
     */
    public static function verify_before_send_mail($contact_form, &$abort) {
        $settings = Human_Guard_Core::get_settings();
        if (!empty($settings['contact_form_auth_only']) && !is_user_logged_in()) {
            $abort = true;
            if (isset($contact_form->skip_mail)) {
                $contact_form->skip_mail = true;
            }
        }
    }
}
