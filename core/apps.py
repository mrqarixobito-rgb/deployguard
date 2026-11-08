from django.apps import AppConfig
from django.core.management import call_command
from django.db.models.signals import post_migrate


def _create_cache_table(sender, **kwargs):
    # Idempotent: skips the table if it already exists.
    call_command("createcachetable", verbosity=0)


class CoreConfig(AppConfig):
    name = "core"

    def ready(self):
        post_migrate.connect(_create_cache_table, sender=self, dispatch_uid="dg_create_cache_table")
