"""Persist incident transitions separately from notification delivery.

A failed webhook must not consume an incident. The caller serializes runs with
an OS lock; SQLite commits state and its notification together. Delivery is at
least once: a process dying after the receiver accepts but before acknowledgement
can cause a duplicate, so every notification carries a stable event identifier.
"""
import json
from pathlib import Path
import sqlite3
import time
import uuid
from .health import Observation


class IncidentStore:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path, timeout=5)
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS target_state (
                name TEXT PRIMARY KEY, state TEXT NOT NULL,
                candidate TEXT NOT NULL, count INTEGER NOT NULL,
                observed_at INTEGER NOT NULL, observation TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbox (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, state TEXT NOT NULL,
                created_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt INTEGER NOT NULL DEFAULT 0
            );
        ''')

    def close(self):
        self.db.close()

    def observe(self, result: Observation, threshold: int = 2, now: int | None = None):
        if not 1 <= threshold <= 10:
            raise ValueError('Invalid transition threshold')
        now = int(time.time()) if now is None else now
        candidate = ('warning' if result.category == 'certificate-expiring' else 'healthy') if result.healthy else 'down'
        with self.db:
            row = self.db.execute('SELECT state,candidate,count FROM target_state WHERE name=?', (result.name,)).fetchone()
            state, previous, count = row if row else ('unknown', '', 0)
            count = min(threshold, count + 1) if previous == candidate else 1
            if count >= threshold and state != candidate:
                # Initial health is quiet; initial warnings/outages are actionable.
                if state != 'unknown' or candidate != 'healthy':
                    self.db.execute('INSERT INTO outbox(id,name,state,created_at) VALUES(?,?,?,?)',
                                    (str(uuid.uuid4()), result.name, candidate, now))
                state = candidate
            self.db.execute('''INSERT INTO target_state VALUES(?,?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET state=excluded.state,
                candidate=excluded.candidate,count=excluded.count,
                observed_at=excluded.observed_at,observation=excluded.observation''',
                (result.name, state, candidate, count, now, json.dumps(result.to_dict())))

    def pending(self, now: int | None = None):
        now = int(time.time()) if now is None else now
        return self.db.execute('SELECT id,name,state,created_at,attempts FROM outbox WHERE next_attempt<=? ORDER BY created_at,rowid LIMIT 20', (now,)).fetchall()

    def delivered(self, event_id: str):
        with self.db:
            self.db.execute('DELETE FROM outbox WHERE id=?', (event_id,))

    def failed(self, event_id: str, now: int | None = None):
        now = int(time.time()) if now is None else now
        with self.db:
            row = self.db.execute('SELECT attempts FROM outbox WHERE id=?', (event_id,)).fetchone()
            if row:
                delay = min(3600, 30 * 2 ** min(row[0], 7))
                self.db.execute('UPDATE outbox SET attempts=attempts+1,next_attempt=? WHERE id=?', (now + delay, event_id))
