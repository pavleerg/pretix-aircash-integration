import time
import requests
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from pretix.presale.utils import event_view
from pretix.base.models import OrderPayment, Event
from pretix.base.payment import PaymentException
from pretix.multidomain.urlreverse import eventreverse

from .payment import AircashProvider

def return_ok(request, **kwargs):
    """
    User returns from Aircash (success redirect).
    """
    event = request.event
    organizer = request.organizer

    order_code = request.GET.get("order_code") or request.GET.get("order")
    pid = request.GET.get("payment_id") or request.GET.get("payment_local_id")
    if not order_code or not pid:
        return redirect(f"/{organizer.slug}/{event.slug}/")

    try:
        payment = OrderPayment.objects.get(
            order__event=event, order__code=order_code, local_id=pid
        )
    except OrderPayment.DoesNotExist:
        return redirect(f"/{organizer.slug}/{event.slug}/")

    time.sleep(2)

    provider = AircashProvider(event)
    try:
        provider.check_payment_status(payment)
    except PaymentException as e:
        print("Aircash check_payment_status failed:", e)

    complete_url = f"/{organizer.slug}/{event.slug}/order/{payment.order.code}/{payment.order.secret}"
    return redirect(complete_url)


def return_cancel(request, organizer, event):
    """
    User returns from Aircash (cancel redirect).
    """
    url = eventreverse(request.event, "presale:event.checkout.payment", kwargs={})
    return redirect(url)


@csrf_exempt
def webhook(request, organizer, event):
    try:
        event_obj = Event.objects.get(slug=event, organizer__slug=organizer)
    except Event.DoesNotExist:
        return HttpResponse(status=404)

    partner_transaction_id = request.GET.get("partnerTransactionId")
    if not partner_transaction_id:
        return HttpResponse(status=200)

    try:
        order_code, local_id = partner_transaction_id.split("-", 1)
        payment = OrderPayment.objects.get(
            order__event=event_obj, order__code=order_code, local_id=local_id
        )
        provider = AircashProvider(event_obj)
        provider.check_payment_status(payment)
    except OrderPayment.DoesNotExist:
        pass
    except Exception as e:
        logger.exception("Webhook error: %s", e)

    return HttpResponse(status=200)