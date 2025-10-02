import logging
from pretix.base.models import OrderPayment
from pretix.celery_app import app
from django_scopes import scope

logger = logging.getLogger(__name__)


@app.task(bind=True, max_retries=0)  # disable retries
def check_aircash_status_task(self, payment_id, organizer_id):
    """
    Celery task that re-checks Aircash payment status after a delay,
    but skips if payment is already marked as paid.
    """
    try:
        with scope(organizer=organizer_id):
            payment = OrderPayment.objects.select_related("order__event").get(id=payment_id)
            logger.info("################# TASK STARTED #################")
            if payment.state == OrderPayment.PAYMENT_STATE_CONFIRMED:
                logger.info("################# Payment %s already confirmed. Skipping Aircash check.", payment.id)
                return

            event = payment.order.event
            from .payment import AircashProvider

            provider = AircashProvider(event)
            finished = provider.check_payment_status(payment)

            logger.info(
                "################# Aircash status check for payment %s (finished=%s)", 
                payment.id, finished
            )

    except OrderPayment.DoesNotExist:
        logger.warning("Payment %s not found (organizer_id=%s)", payment_id, organizer_id)
    except Exception as e:
        logger.exception("Error while checking Aircash status: %s", e)
        # no retry
