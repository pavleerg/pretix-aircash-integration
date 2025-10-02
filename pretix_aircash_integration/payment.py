from collections import OrderedDict
import logging
import requests
from django import forms
from django.utils.translation import gettext_lazy as _
from django.template.loader import render_to_string
from pretix.base.payment import BasePaymentProvider, PaymentException
from pretix.base.models import OrderPayment
from pretix.multidomain.urlreverse import build_absolute_uri
from .utils import build_data_to_sign, generate_signature, query_aircash_status
from django.utils.safestring import mark_safe
from django.templatetags.static import static
import os
import logging
import json
logger = logging.getLogger(__name__)


class AircashProvider(BasePaymentProvider):
    """
    Pretix payment provider for Aircash QR/Redirect.
    Handles payment initiation, status checks, and Pretix UI integration.
    """

    identifier = "aircash"
    verbose_name = _("Aircash (QR/Redirect)")
    public_name = _("Aircash")

    execute_payment_needs_user = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_base = os.getenv("AIRCASH_API_BASE")
        self.partner_id = os.getenv("AIRCASH_PARTNER_ID")
        self.certificate_path = os.getenv("AIRCASH_CERT_PATH")
        self.certificate_pass = os.getenv("AIRCASH_CERT_PASS")
        self.public_key_path = os.getenv("AIRCASH_PUBLIC_KEY_PATH")
    
    def payment_form_render(self, request, total, order=None) -> str:
        """
        Render explanatory HTML (with Aircash logo) in the payment screen.
        """
        logo_url = static("pretix_aircash_integration/img/aircash-logo.png")
        html = (
            f'<div style="text-align: center; margin-bottom: 1em;">'
            f'  <img src="{logo_url}" alt="Aircash logo" '
            f'       style="max-width: 150px; height: auto;" />'
            f'</div>'
            f'<p>{_("Pay with the Aircash app. You’ll be redirected to approve the payment.")}</p>'
        )
        return mark_safe(html)

    def checkout_confirm_render(self, request, order=None, info_data=None):
        """
        Message shown on Pretix confirm screen before redirect.
        """
        logo_url = static("pretix_aircash_integration/img/aircash-logo.png")
        html = (
            f'<div style="text-align: center; margin-bottom: 1em;">'
            f'  <img src="{logo_url}" alt="Aircash logo" '
            f'       style="max-width: 150px; height: auto;" />'
            f'</div>'
            f'<p>{_("Pay with the Aircash app. You’ll be redirected to approve the payment.")}</p>'
        )
        return mark_safe(html)

    def execute_payment(self, request, payment: OrderPayment) -> str:
        """
        Called after user presses "Confirm order".
        Builds payload, signs it, sends to Aircash, and returns redirect URL.
        """
        if payment.order.status == "p":
            raise PaymentException("Order already paid. Cannot start a new payment.")
        
        return_success = build_absolute_uri(
            self.event, "plugins:pretix_aircash_integration:aircash_return"
        ) + f"?order={payment.order.code}&payment_local_id={payment.local_id}"

        return_decline = build_absolute_uri(
            self.event, "plugins:pretix_aircash_integration:aircash_cancel"
        ) + f"?order={payment.order.code}&payment_local_id={payment.local_id}"

        webhook_url = build_absolute_uri(
            self.event, "plugins:pretix_aircash_integration:aircash_webhook"
        )

        partner_transaction_id = f"{payment.order.code}-{payment.local_id}"
        partner_user_id = payment.order.email or payment.order.code

        payload = {
            "PartnerId": self.partner_id,
            "PartnerUserId": partner_user_id,
            "PartnerTransactionId": partner_transaction_id,
            "Amount": float(payment.amount),
            "CurrencyId": 978, 
            "PayType": 0,
            "PayMethod": 2,
            "NotificationUrl": webhook_url,
            "SuccessUrl": return_success,
            "DeclineUrl": return_decline,
            "CancelUrl": return_decline,
            "OriginUrl": "",
            "Locale": "en-HR",
        }

        data_to_sign = build_data_to_sign(payload)
        payload["Signature"] = generate_signature(
            data_to_sign,
            certificate_path=self.certificate_path,
            certificate_pass=self.certificate_pass,
        )

        resp = requests.post(
            self.api_base.rstrip("/") + "/initiate",
            json=payload,
            timeout=30,
        )
        if resp.status_code != 200:
            raise PaymentException("Aircash API error: " + resp.text)

        data = resp.json()

        url = data.get("url")
        if not url:
            raise PaymentException("Aircash response missing URL")
        
        from .tasks import check_aircash_status_task

        check_aircash_status_task.apply_async(
            args=[payment.id, self.event.organizer.id],
            countdown=30
        )

        return url

    def _apply_status(self, payment: OrderPayment, status: int) -> bool:
        """
        Map Aircash status codes to Pretix payment states.
        Returns True if final, False if still pending.
        """
        if status == 2:      # success
            payment.confirm()
            return True
        elif status == 1:    # declined
            payment.fail()
            return True
        elif status in (3, 5):  # cancelled
            payment.cancel()
            return True
        elif status in (0, 4):  # still pending
            return False
        else:
            raise PaymentException(f"Unknown Aircash status: {status}")

    def check_payment_status(self, payment: OrderPayment):
        """
        Check current payment status via Aircash API and update Pretix state.
        """
        result = query_aircash_status(payment, self)
        status = result.get("status")
        return self._apply_status(payment, status)

    def payment_is_pending(self, payment: OrderPayment) -> bool:
        """
        Let Pretix know when this payment is still pending.
        """
        return payment.state == OrderPayment.PAYMENT_STATE_PENDING
    
    def payment_prepare(self, request, payment):
        # Always disallow retries / re-payment
        # Return False or raise exception so Pretix will block the retry
        return False
    
    @property
    def abort_pending_allowed(self) -> bool:
        return False
    
    def payment_can_retry(self, payment: OrderPayment) -> bool:
        return False

    def payment_pending_render(self, request, payment: OrderPayment) -> str:
        """
        Shown on order page while still pending.
        Tries a status check; if still pending, shows message.
        """
        # try:
        #     result = query_aircash_status(payment, self)
        #     status = result.get("status") or result.get("Status")
        #     self._apply_status(payment, status)
        # except PaymentException as e:
        #     logger.warning("Aircash status check failed: %s", e)

        return render_to_string(
            "pretix_aircash_integration/pending_box.html",
            {"text": _("Waiting for Aircash to confirm your payment…")},
            request=request,
        )

    def payment_control_render_short(self, payment: OrderPayment) -> str:
        """
        Short identifier shown in Pretix admin lists.
        """
        tx = (payment.info_data or {}).get("tx_id")
        return f"Aircash • {tx or f'local:{payment.local_id}'}"

    def api_payment_details(self, payment: OrderPayment):
        """
        Expose details via Pretix REST API.
        """
        return payment.info_data or {}

    def matching_id(self, payment: OrderPayment):
        """
        Match internal or external transaction ID.
        """
        return (payment.info_data or {}).get("tx_id") or str(payment.local_id)

    def payment_is_valid_session(self, request) -> bool:
        """
        Always allow returning user sessions.
        """
        return True
    
    



