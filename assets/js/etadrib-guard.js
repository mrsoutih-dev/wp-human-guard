/**
 * Etadrib Human Guard Client Verification
 */
(function() {
    'use strict';

    function initHumanGuard() {
        // Find any math input and autofocus or enhance
        var mathInputs = document.querySelectorAll('input[name="et_guard_math_ans"]');
        mathInputs.forEach(function(input) {
            input.setAttribute('inputmode', 'numeric');
        });

        // Ensure forms validate math answer presence before client submit
        var forms = document.querySelectorAll('form#registerform, form#tutor-registration-form, form.woocommerce-form-register');
        forms.forEach(function(form) {
            form.addEventListener('submit', function(e) {
                var mathField = form.querySelector('input[name="et_guard_math_ans"]');
                if (mathField && mathField.value.trim() === '') {
                    e.preventDefault();
                    mathField.focus();
                    mathField.style.borderColor = '#ef4444';
                    var note = form.querySelector('.et-guard-validation-msg');
                    if (!note) {
                        note = document.createElement('div');
                        note.className = 'et-guard-validation-msg';
                        note.style.color = '#dc2626';
                        note.style.fontSize = '13px';
                        note.style.marginTop = '6px';
                        note.style.fontWeight = '600';
                        note.textContent = 'يرجى كتابة إجابة التحقق البشري للمتابعة.';
                        mathField.parentNode.appendChild(note);
                    }
                }
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initHumanGuard);
    } else {
        initHumanGuard();
    }
})();
