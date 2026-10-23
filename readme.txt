=== HumanGuard - Anti-Bot & Registration Security ===
Contributors: zohodigital
Tags: anti-bot, spam protection, registration guard, honeypot, security, tutor lms, woocommerce
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Advanced multi-layer anti-bot & human verification system for WordPress, Tutor LMS, and WooCommerce. Built by zohodigital.com.

== Description ==

HumanGuard is a production-grade WordPress security plugin built by zohodigital.com to eliminate bot registrations, credential stuffing brute-force attacks, and XML-RPC exploits.

= Features =
* Invisible Honeypot Trap
* Time Trap Submission Validation
* Dynamic JavaScript Proof of Browser Execution
* Interactive Smart Math Verification (Arabic & English)
* Disposable & Fake Email Blacklist
* XML-RPC Attack Blocker
* IP Rate Limiting & Brute-Force Lockout
* Native Tutor LMS & WooCommerce Integration
* Admin Dashboard with 1-Click Bot Account Cleanup
* Contact Form 7 Protection & Authenticated Members-Only Access Control

== Installation ==

1. Upload the `wp-human-guard` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Access configuration via 'HumanGuard' in your admin menu.

== Frequently Asked Questions ==

= Does this plugin work without external API keys? =
Yes! Out of the box, all core features (Honeypot, Time Trap, Dynamic JS Token, and Smart Math Challenge) run completely standalone without requiring any third-party APIs. Cloudflare Turnstile is also supported optionally.

== Changelog ==

= 1.1.0 =
* Added Contact Form Protection module.
* Added Member-Only Access Control for contact forms to block bot emails and unauthorized submissions.
* Added auto-lock & pre-fill of verified member email & name.
* Added direct POST and REST API abuse shield for Contact Form 7.

= 1.0.0 =
* Initial public release by zohodigital.com.
