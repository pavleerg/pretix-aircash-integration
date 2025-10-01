import logging
from pretix.base.models import OrderPayment, Event
from pretix.celery_app import app
from .payment import AircashProvider

logger = logging.getLogger(__name__)

@app.task(bind=True, max_retries=3)
def check_aircash_status_task(self, event_id, payment_id):
    try:
        event = Event.objects.get(id=event_id)
        payment = OrderPayment.objects.get(id=payment_id, order__event=event)
        provider = AircashProvider(event)
        finished = provider.check_payment_status(payment)
        logger.info("Aircash status check for payment %s: finished=%s", payment.id, finished)
    except OrderPayment.DoesNotExist:
        logger.warning("Payment %s not found for event %s", payment_id, event_id)
    except Exception as e:
        logger.exception("Error while checking Aircash status: %s", e)
        raise self.retry(exc=e, countdown=60)
