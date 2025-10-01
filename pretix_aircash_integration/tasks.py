import logging
from pretix.base.models import OrderPayment, Event
from pretix.celery_app import app
from django_scopes import scope

logger = logging.getLogger(__name__)

@app.task(bind=True, max_retries=3)
def check_aircash_status_task(self, payment_id, organizer_slug, event_slug):
    try:
        with scope(organizer=organizer_slug):
            payment = OrderPayment.objects.select_related("order__event").get(id=payment_id)
            event = payment.order.event

            from .payment import AircashProvider
            provider = AircashProvider(event)
            finished = provider.check_payment_status(payment)

            logger.info(
                "Aircash status check for payment %s: finished=%s",
                payment.id,
                finished
            )

    except OrderPayment.DoesNotExist:
        logger.warning("Payment %s not found (org=%s, event=%s)", payment_id, organizer_slug, event_slug)
    except Exception as e:
        logger.exception("Error while checking Aircash status: %s", e)
        raise self.retry(exc=e, countdown=60)
