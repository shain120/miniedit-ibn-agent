"""Bounded background jobs that report through the application's UI queue."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from threading import Event, Lock
from time import monotonic, sleep
from traceback import format_exc
from uuid import uuid4


class JobState(str, Enum):
    QUEUED = 'QUEUED'; DISCOVERING = 'DISCOVERING'; RUNNING = 'RUNNING'; WAITING = 'WAITING'; VERIFYING = 'VERIFYING'; SUCCESS = 'SUCCESS'
    FAILED = 'FAILED'; CANCEL_REQUESTED = 'CANCEL_REQUESTED'; CANCELLED = 'CANCELLED'


ACTIVE_STATES = frozenset({JobState.QUEUED, JobState.DISCOVERING, JobState.RUNNING, JobState.WAITING,
                           JobState.VERIFYING, JobState.CANCEL_REQUESTED})
TERMINAL_STATES = frozenset({JobState.SUCCESS, JobState.FAILED, JobState.CANCELLED})
LEGAL_TRANSITIONS = {
    JobState.QUEUED: {JobState.DISCOVERING, JobState.RUNNING, JobState.WAITING, JobState.CANCEL_REQUESTED, JobState.CANCELLED, JobState.FAILED},
    JobState.DISCOVERING: {JobState.RUNNING, JobState.WAITING, JobState.VERIFYING, JobState.CANCEL_REQUESTED, JobState.CANCELLED, JobState.SUCCESS, JobState.FAILED},
    JobState.RUNNING: {JobState.DISCOVERING, JobState.WAITING, JobState.VERIFYING, JobState.CANCEL_REQUESTED, JobState.CANCELLED, JobState.SUCCESS, JobState.FAILED},
    JobState.WAITING: {JobState.RUNNING, JobState.VERIFYING, JobState.CANCEL_REQUESTED, JobState.CANCELLED, JobState.SUCCESS, JobState.FAILED},
    JobState.VERIFYING: {JobState.RUNNING, JobState.WAITING, JobState.CANCEL_REQUESTED, JobState.CANCELLED, JobState.SUCCESS, JobState.FAILED},
    JobState.CANCEL_REQUESTED: {JobState.CANCELLED, JobState.FAILED},
    JobState.CANCELLED: set(), JobState.SUCCESS: set(), JobState.FAILED: set(),
}


@dataclass
class Job:
    job_id: str
    type: str
    title: str
    state: JobState = JobState.QUEUED
    progress: int | None = None
    message: str = ''
    started_at: float | None = None
    finished_at: float | None = None
    error: str = ''
    result: object = None
    cancel_event: Event = field(default_factory=Event, repr=False)

    def as_event(self, event_type='job_changed'):
        return {'type': event_type, 'job': self}


class JobManager:
    """Never calls Tk. `event_sink` must marshal work to the UI thread."""
    def __init__(self, event_sink, max_workers=4):
        self._sink, self._executor = event_sink, ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='chatmininet-job')
        self._jobs, self._history, self._lock, self._accepting = {}, [], Lock(), True

    def _transition(self, job, state, message=None):
        """Apply a legal one-way job state transition under the manager lock."""
        state = JobState(state)
        with self._lock:
            if job.state == state:
                if message is not None and state not in TERMINAL_STATES:
                    job.message = str(message)
                return False
            if state not in LEGAL_TRANSITIONS[job.state]:
                return False
            job.state = state
            if message is not None:
                job.message = str(message)
            if state in TERMINAL_STATES:
                # Activity wording belongs only to active states.
                job.message = ''
                job.finished_at = monotonic()
                self._history.append({
                    'job_id': job.job_id, 'type': job.type, 'title': job.title,
                    'state': job.state.value, 'message': job.error or 'Completed',
                    'started_at': job.started_at, 'finished_at': job.finished_at,
                })
                self._history = self._history[-100:]
        return True

    def submit(self, job_type, title, work):
        with self._lock:
            if not self._accepting:
                raise RuntimeError('Job manager is shutting down.')
            job = Job(uuid4().hex, job_type, title); self._jobs[job.job_id] = job
        self._sink(job.as_event('job_started'))
        self._executor.submit(self._run, job, work)
        return job

    def _run(self, job, work):
        with self._lock:
            job.started_at = monotonic()
        self._transition(job, JobState.RUNNING, 'Working…'); self._sink(job.as_event())
        def progress(message, value=None, state=None):
            with self._lock:
                if job.state in TERMINAL_STATES or job.state == JobState.CANCEL_REQUESTED:
                    return
                job.message, job.progress = str(message or ''), value
            if state:
                self._transition(job, JobState(state), message)
            self._sink(job.as_event('job_progress'))
        try:
            if job.cancel_event.is_set():
                self._transition(job, JobState.CANCELLED)
            else:
                job.result = work(job.cancel_event, progress)
                self._transition(job, JobState.CANCELLED if job.cancel_event.is_set() else JobState.SUCCESS)
        except Exception as exc:  # Worker boundary: UI receives a safe failure event.
            with self._lock:
                job.error, job.result = str(exc), {'traceback': format_exc()}
            self._transition(job, JobState.FAILED)
        self._sink(job.as_event('job_completed'))

    def request_cancel(self, job_id):
        with self._lock: job = self._jobs.get(job_id)
        if not job or job.state not in ACTIVE_STATES - {JobState.CANCEL_REQUESTED}: return False
        job.cancel_event.set()
        if not self._transition(job, JobState.CANCEL_REQUESTED, 'Cancellation requested.'):
            return False
        self._sink(job.as_event()); return True

    def active(self):
        with self._lock:
            return [job for job in self._jobs.values() if job.state in ACTIVE_STATES]

    def history(self):
        with self._lock:
            return list(self._history)

    def begin_shutdown(self):
        with self._lock: self._accepting = False; ids = list(self._jobs)
        for job_id in ids: self.request_cancel(job_id)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def submit_responsiveness_probe(self, duration_seconds=15):
        """Developer diagnostic: keeps a worker busy without ever touching Tk."""
        def probe(cancel_event, progress):
            deadline = monotonic() + duration_seconds
            while monotonic() < deadline:
                if cancel_event.is_set(): return {'cancelled': True}
                progress('Responsiveness probe running…')
                sleep(.1)
            return {'duration_seconds': duration_seconds}
        return self.submit('TOPOLOGY_OPERATION', 'UI responsiveness probe', probe)
