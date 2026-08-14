"""Alembic environment.

Migrations run as ``migration_owner`` (§8.6), never as the runtime role — the
runtime role must not own any table or RLS would not apply to it. The URL comes
from MIGRATION_DATABASE_URL so there is no way to point alembic at the app
connection by accident.
"""

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

url = os.environ.get("MIGRATION_DATABASE_URL")
if not url:
    raise RuntimeError(
        "MIGRATION_DATABASE_URL is not set. Migrations must connect as "
        "migration_owner (see db/roles.sql and scripts/init_db.sh)."
    )
config.set_main_option("sqlalchemy.url", url)

target_metadata = None


def run_migrations_offline() -> None:
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
