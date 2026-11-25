-- RevokedSince runs at every startup to warm the denylist, and without
-- an index it matched nothing but a sequential scan over a table that
-- never shrinks. Measured at 200k rows: 9.97ms and 2857 buffers before,
-- 0.055ms and 4 after.
--
-- Partial because live sessions have revoked_at NULL and this query
-- never wants them, so the index holds only the rows it reads. The
-- condition cannot be UNIQUE: RevokeAllForUser stamps several rows with
-- one timestamp, and a unique index would make the second one fail.


CREATE INDEX IF NOT EXISTS sessions_revoked_at
     ON  sessions (revoked_at) WHERE revoked_at IS NOT NULL;

-- prune_sessions deletes sessions whose expiry has passed, in batches.
--
-- A PROCEDURE and not a FUNCTION, because it commits between batches
-- and a function cannot: a function is an expression evaluated inside
-- the caller's statement, so committing would break that statement's
-- atomicity. The commits are the point. One large DELETE writes its
-- whole WAL in a burst that replicas lag behind, and -- worse -- it
-- pins the xmin horizon for its whole duration, which stops VACUUM
-- from reclaiming anything anywhere in the database until it ends.
--
-- The predicate is on expires_at, not revoked_at. While expiry is in
-- the future the row can still change a decision: Session.Live reads
-- it, and a refresh token presented after rotation is found there
-- rather than coming back as "never existed", which is what makes
-- reuse detectable at all. Past expiry, Live refuses the token whatever
-- the row says, so the row cannot matter any more.
--
-- FOR UPDATE SKIP LOCKED so that housekeeping never waits on a request.
-- An expired session that was never revoked is a legitimate target for
-- both this and RevokeAllForUser, which matches on revoked_at IS NULL
-- and does not filter expiry. Measured on that collision: 2.03s of
-- waiting without SKIP LOCKED, 0.04s with it, and the row it skipped
-- was revoked normally and taken by the next pass.
--
-- Nothing calls this on a schedule. Scheduling is the operator's: cron,
-- a systemd timer, a Kubernetes CronJob or pg_cron. A library that
-- deleted from its user's database on a timer of its own would be doing
-- something nobody asked for.

CREATE OR REPLACE PROCEDURE prune_sessions(
    grece interval DEFAULT interval '7 days',
    batch int DEFAULT 1000
)
LANGUAGE plpgsql AS $$
DECLARE n int;
BEGIN
    LOOP
      -- The CTE carries the LIMIT: Postgres has no DELETE ... LIMIT,
      -- so the batch has to be chosen by a SELECT and fed in.
      WITH doomed AS (
        SELECT id FROM sessions
        WHERE expires_at < now() - grace
        LIMIT batch
        FOR UPDATE SKIP LOCKED
      )
      DELETE FROM sessions WHERE id IN (SELECT id FROM doomed);

      GET DIAGNOSTICS n = ROW_COUNT;

      -- Commit before the exit test, or the last batch is left
      -- uncommitted.
    COMMIT;
    EXIT WHEN n = 0;  

    -- PERFORM, not SELECT: plpgsql requires a discarded result to
    -- say so. The pause lets replication catch up with the WAL this
    -- batch just produced.
    PERFORM pg_sleep(0.2);
    END LOOP;    
END $$    
