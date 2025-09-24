from django.utils.translation import gettext_lazy

from . import __version__

try:
    from pretix.base.plugins import PluginConfig
except ImportError:
    raise RuntimeError("Please use pretix 2.7 or above to run this plugin!")


class PluginApp(PluginConfig):
    default = True
    name = "pretix_aircash_integration"
    verbose_name = "AircashIntegration"

    class PretixPluginMeta:
        name = gettext_lazy("AircashIntegration")
        author = "Pavle Ergović"
        description = gettext_lazy("A plugin to allow Aircash as a payment option")
        visible = True
        version = __version__
        category = "INTEGRATION"
        compatibility = "pretix>=2.7.0"
        settings_links = []
        navigation_links = []

    def ready(self):
        from . import signals  # NOQA
