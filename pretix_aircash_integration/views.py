import time
import requests
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt

from pretix.base.models import OrderPayment
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
    """
    Aircash webhook: GET ?partnerTransactionId=ORDER-localid
    Runs status check and updates payment state.
    """
    partner_transaction_id = request.GET.get("partnerTransactionId")
    if not partner_transaction_id:
        return HttpResponse(status=400)

    try:
        order_code, local_id = partner_transaction_id.split("-", 1)
    except ValueError:
        return HttpResponse(status=400)

    try:
        payment = OrderPayment.objects.get(
            order__event=event, order__code=order_code, local_id=local_id
        )
    except OrderPayment.DoesNotExist:
        return HttpResponse(status=404)

    provider = AircashProvider(event)
    try:
        provider.check_payment_status(payment)
    except PaymentException:
        return HttpResponse(status=500)

    return HttpResponse(status=200)
