"""Everything about a schema that a migration round trip, a restore or a destructive experiment must
leave unchanged (D64 step 5, ACCEPTANCE 5.78).

``snapshot_schema(conn)`` returns ``{"<kind>:<name>": "<facts>"}``; ``diff(before, after)`` says
what differs. It exists because the *comparison itself* was the weak point twice:

* a restore after an experiment compared constraint **definitions** and so missed that the
  constraint had lost its **COMMENT** (dropping and re-adding a constraint does that; the dev
  database lost the 0021 comment this way and nothing noticed until a test read it);
* the round-trip fingerprint in ``test_migrations_roundtrip`` listed columns, constraints, policies,
  indexes, trigger names, function bodies and grants, and no comment of any kind.

What is covered, per kind: **column** (type, NOT NULL, default, identity, generated, ACL, COMMENT),
**relation** (kind, owner, RLS and FORCE RLS flags, ACL, reloptions, COMMENT), **constraint**
(definition, validated, deferrable, COMMENT), **index** (definition, valid, COMMENT), **trigger**
(definition, enabled state, COMMENT), **policy** (command, roles, USING, WITH CHECK), **function**
(full definition, owner, SECURITY DEFINER, ``SET`` config such as ``search_path``, ACL, COMMENT),
**view**, **role** (attributes), **default_acl**, **database** (owner and ACL: who may connect, make
temporary tables, create), **alembic** (revision). Role facts and the database's own ACL are
cluster- or database-wide; everything else is limited to ``schema``. The schema's own name is
replaced by ``<schema>`` in every value, so a scratch schema and ``public`` can be compared with
each other.

Not covered, on purpose: row data (that is the tests' job), statistics, storage parameters beyond
``reloptions``, and objects outside the schema.
"""

from __future__ import annotations

from sqlalchemy import Connection, text

#: One query per kind, each returning (name, facts) and taking ``:s`` (the schema name).
QUERIES: dict[str, str] = {
    "column": """
        SELECT c.relname || '.' || a.attname,
               format_type(a.atttypid, a.atttypmod) || ' notnull=' || a.attnotnull
               || ' default=' || coalesce(pg_get_expr(d.adbin, d.adrelid), '')
               || ' identity=' || a.attidentity::text || ' generated=' || a.attgenerated::text
               || ' acl=' || coalesce(a.attacl::text, '')
               || ' comment=' || coalesce(col_description(a.attrelid, a.attnum), '')
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
        LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE c.relnamespace = CAST(:s AS regnamespace) AND c.relkind IN ('r', 'p', 'v')
          AND a.attnum > 0 AND NOT a.attisdropped""",
    "relation": """
        SELECT c.relname,
               c.relkind::text || ' owner=' || pg_get_userbyid(c.relowner)
               || ' rls=' || c.relrowsecurity || ' force=' || c.relforcerowsecurity
               || ' acl=' || coalesce(c.relacl::text, '')
               || ' opts=' || coalesce(c.reloptions::text, '')
               || ' comment=' || coalesce(obj_description(c.oid, 'pg_class'), '')
        FROM pg_class c
        WHERE c.relnamespace = CAST(:s AS regnamespace) AND c.relkind IN ('r', 'p', 'v', 'S')""",
    "constraint": """
        SELECT r.relname || '.' || c.conname,
               c.contype::text || ' ' || pg_get_constraintdef(c.oid)
               || ' validated=' || c.convalidated || ' deferrable=' || c.condeferrable
               || ' comment=' || coalesce(obj_description(c.oid, 'pg_constraint'), '')
        FROM pg_constraint c JOIN pg_class r ON r.oid = c.conrelid
        WHERE r.relnamespace = CAST(:s AS regnamespace)""",
    "index": """
        SELECT c.relname,
               pg_get_indexdef(i.indexrelid) || ' valid=' || i.indisvalid
               || ' comment=' || coalesce(obj_description(i.indexrelid, 'pg_class'), '')
        FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
        WHERE c.relnamespace = CAST(:s AS regnamespace)""",
    "trigger": """
        SELECT r.relname || '.' || t.tgname,
               pg_get_triggerdef(t.oid) || ' enabled=' || t.tgenabled::text
               || ' comment=' || coalesce(obj_description(t.oid, 'pg_trigger'), '')
        FROM pg_trigger t JOIN pg_class r ON r.oid = t.tgrelid
        WHERE r.relnamespace = CAST(:s AS regnamespace) AND NOT t.tgisinternal""",
    "policy": """
        SELECT tablename || '.' || policyname,
               cmd || ' permissive=' || permissive || ' roles=' || roles::text
               || ' using=' || coalesce(qual, '') || ' check=' || coalesce(with_check, '')
        FROM pg_policies WHERE schemaname = :s""",
    "function": """
        SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
               pg_get_functiondef(p.oid) || ' owner=' || pg_get_userbyid(p.proowner)
               || ' secdef=' || p.prosecdef || ' config=' || coalesce(p.proconfig::text, '')
               || ' acl=' || coalesce(p.proacl::text, '')
               || ' comment=' || coalesce(obj_description(p.oid, 'pg_proc'), '')
        FROM pg_proc p
        WHERE p.pronamespace = CAST(:s AS regnamespace) AND p.prokind = 'f'""",
    "view": """
        SELECT c.relname, pg_get_viewdef(c.oid)
        FROM pg_class c WHERE c.relnamespace = CAST(:s AS regnamespace) AND c.relkind = 'v'""",
    "role": """
        SELECT rolname, 'super=' || rolsuper || ' createrole=' || rolcreaterole
               || ' createdb=' || rolcreatedb || ' login=' || rolcanlogin
               || ' bypassrls=' || rolbypassrls
        FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' AND rolname <> 'postgres'""",
    "default_acl": """
        SELECT defaclrole::regrole::text || defaclobjtype::text, defaclacl::text
        FROM pg_default_acl""",
    # database-wide, not the schema's: the privileges PUBLIC and the roles hold on the database
    # (CONNECT, TEMPORARY, CREATE). Migration 0023 revokes TEMPORARY from PUBLIC and its downgrade
    # grants it; a round trip that is killed in the middle leaves it granted (completion 5)
    "database": """
        SELECT 'acl', 'owner=' || pg_get_userbyid(datdba) || ' acl=' || coalesce(datacl::text, '')
        FROM pg_database WHERE datname = current_database()""",
}

#: Read only when the schema has the table (a scratch schema before the first migration has not).
ALEMBIC = "SELECT 'version', version_num FROM alembic_version"


def snapshot_schema(conn: Connection, schema: str = "public") -> dict[str, str]:
    """Every fact of ``schema`` listed in the module docstring, as ``{"kind:name": "facts"}``."""
    out: dict[str, str] = {}
    for kind, sql in QUERIES.items():
        for name, value in conn.execute(text(sql), {"s": schema}).all():
            out[f"{kind}:{name}".replace(schema, "<schema>")] = str(value).replace(
                schema, "<schema>")
    has_version = conn.execute(
        text("SELECT to_regclass(:t)"), {"t": f"{schema}.alembic_version"}).scalar_one()
    if has_version is not None:
        for name, value in conn.execute(text(ALEMBIC.replace(
                "alembic_version", f"{schema}.alembic_version"))).all():
            out[f"alembic:{name}"] = str(value)
    return out


def diff(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """Human-readable differences; empty means identical."""
    lines = []
    for key in sorted(set(before) | set(after)):
        if key not in after:
            lines.append(f"- missing after: {key}")
        elif key not in before:
            lines.append(f"+ new after:     {key}")
        elif before[key] != after[key]:
            b, a = before[key], after[key]
            i = next((n for n, (x, y) in enumerate(zip(b, a, strict=False)) if x != y),
                     min(len(a), len(b)))
            lines.append(f"~ changed:       {key}  [...{b[max(0, i - 30):i + 60]!r}] -> "
                         f"[...{a[max(0, i - 30):i + 60]!r}]")
    return lines
