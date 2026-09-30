"""The frozen Baseline Global Snapshot (ACCEPTANCE 5.20, D54).

Revision ID: 0015
Revises: 0014

§4.5 (v0.2): ``Effective Policy = Baseline Global Snapshot (frozen when the engagement is
created) ∩ Emergency Overlay (live) ∩ Customer ∩ Engagement``. Until now every layer was
live-merged, so a later global baseline reached every open engagement -- and could widen it.
``docs/D54_POLICY_SNAPSHOT_FREEZE_DESIGN.md`` has the analysis; decided at D54:

* only the *global baseline* freezes (``layer = 'baseline_global' AND engagement_id IS NULL``);
  customer and engagement layers, and the emergency overlay, stay live;
* a baseline published after the freeze never reaches the engagement, tightening or widening;
  only an overlay (tighten-only, written by ``global_policy_admin``) does;
* a baseline row that was in force at the freeze **stays** in force for that engagement even if
  it is retired later -- the freeze is the baseline the customer signed against, not "whatever
  hasn't been retired since";
* a pointer, not a copy: the engagement stores one number and the rows are immutable
  (0013, 0014); an engagement with no number is not frozen ("absent means unknown", D30).

"Stays in force after being retired" needs one thing a boundary on ``id`` alone cannot give: **when,
relative to the freeze, a row was retired**. ``id`` orders publications but not retirements, and
comparing a retirement's ``max(id)`` with a freeze's ``max(id)`` is ambiguous whenever nothing was
published between them. So all three events -- a layer's publication, a layer's retirement and an
engagement's freeze -- take their position from **one sequence**, ``policy_change_seq``, and a row
has one life ``[created_seq, deactivated_seq)``:

* ``policy_layers.created_seq`` and ``.deactivated_seq`` are stamped by a trigger (SECURITY
  DEFINER, so the roles need no grant on the sequence and cannot write either column: 0013 left
  them ``UPDATE (active)`` alone, and an INSERT's supplied value is overwritten);
* a retired layer cannot be reactivated -- a second life would break the interval. The code never
  did; the tests that flipped ``active`` back no longer do. Re-publish instead;
* ``engagements.baseline_frozen_through`` is the freeze point, allocated by
  ``policy_freeze_point()`` (SECURITY DEFINER, EXECUTE for ``registry_admin`` only, the role that
  creates engagements). The runtime role cannot write the column (0013's column list).

A baseline row is in force for a frozen engagement iff
``COALESCE(created_seq, 0) < frozen AND (active OR deactivated_seq > frozen)``. Rows that pre-date
this migration have no ``created_seq`` (read as 0: older than every freeze) and, if retired, no
``deactivated_seq`` (retired before any freeze, so not in force). No back-fill is needed and none
is a guess.
"""

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SEQUENCE policy_change_seq;")
    op.execute("ALTER TABLE policy_layers ADD COLUMN created_seq BIGINT;")
    op.execute("ALTER TABLE policy_layers ADD COLUMN deactivated_seq BIGINT;")
    op.execute("ALTER TABLE engagements ADD COLUMN baseline_frozen_through BIGINT;")
    op.execute("""
COMMENT ON COLUMN engagements.baseline_frozen_through IS
'§4.5 / 5.20 (D54): the position, in policy_change_seq, at which this engagement froze the global
baseline. NULL = no freeze recorded (an engagement created before 0015): its baseline is live, as
it always was. Written once by create_engagement; the runtime role cannot write it.';
""")

    op.execute("""
CREATE FUNCTION policy_layers_stamp() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.created_seq := nextval('policy_change_seq');
        NEW.deactivated_seq := NULL;
        RETURN NEW;
    END IF;
    -- UPDATE: only `active` is writable, and only downwards.
    IF OLD.active IS TRUE AND NEW.active IS NOT TRUE THEN
        NEW.deactivated_seq := nextval('policy_change_seq');
    ELSIF OLD.active IS NOT TRUE AND NEW.active IS TRUE THEN
        RAISE EXCEPTION
            'policy layer % stays retired: re-publish it instead of reactivating it '
            '(a frozen baseline is defined by when a layer was in force)', OLD.id;
    END IF;
    NEW.created_seq := OLD.created_seq;
    IF NEW.active IS TRUE THEN
        NEW.deactivated_seq := NULL;
    ELSIF OLD.deactivated_seq IS NOT NULL THEN
        NEW.deactivated_seq := OLD.deactivated_seq;
    END IF;
    RETURN NEW;
END $$;
""")
    op.execute("""
CREATE TRIGGER policy_layers_stamp_insert BEFORE INSERT ON policy_layers
    FOR EACH ROW EXECUTE FUNCTION policy_layers_stamp();
""")
    op.execute("""
CREATE TRIGGER policy_layers_stamp_update BEFORE UPDATE ON policy_layers
    FOR EACH ROW EXECUTE FUNCTION policy_layers_stamp();
""")

    op.execute("""
CREATE FUNCTION policy_freeze_point() RETURNS BIGINT
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT nextval('policy_change_seq')
$$;
""")
    op.execute("REVOKE ALL ON FUNCTION policy_freeze_point() FROM PUBLIC;")
    op.execute("GRANT EXECUTE ON FUNCTION policy_freeze_point() TO registry_admin;")


def downgrade() -> None:
    op.execute("REVOKE EXECUTE ON FUNCTION policy_freeze_point() FROM registry_admin;")
    op.execute("DROP FUNCTION IF EXISTS policy_freeze_point();")
    op.execute("DROP TRIGGER IF EXISTS policy_layers_stamp_update ON policy_layers;")
    op.execute("DROP TRIGGER IF EXISTS policy_layers_stamp_insert ON policy_layers;")
    op.execute("DROP FUNCTION IF EXISTS policy_layers_stamp();")
    op.execute("ALTER TABLE engagements DROP COLUMN IF EXISTS baseline_frozen_through;")
    op.execute("ALTER TABLE policy_layers DROP COLUMN IF EXISTS deactivated_seq;")
    op.execute("ALTER TABLE policy_layers DROP COLUMN IF EXISTS created_seq;")
    op.execute("DROP SEQUENCE IF EXISTS policy_change_seq;")
