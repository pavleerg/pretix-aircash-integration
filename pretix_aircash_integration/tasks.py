import logging
from pretix.base.models import OrderPayment, Event
from pretix.celery_app import app
from django_scopes import scope

logger = logging.getLogger(__name__)


@app.task(bind=True, max_retries=3)
def check_aircash_status_task(self, payment_id, organizer_id):
    """
    Celery task that re-checks Aircash payment status after a delay.
    """
    try:
        with scope(organizer=organizer_id):
            payment = OrderPayment.objects.select_related("order__event").get(id=payment_id)
            event = payment.order.event

            from .payment import AircashProvider
            provider = AircashProvider(event)

            finished = provider.check_payment_status(payment)

    except OrderPayment.DoesNotExist:
        logger.warning("Payment %s not found (organizer_id=%s)", payment_id, organizer_id)
    except Exception as e:
        raise self.retry(exc=e, countdown=60)
