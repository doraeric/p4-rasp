from collections.abc import Callable
import threading
from threading import Event, Thread


# https://stackoverflow.com/questions/12317940
def orify(e, changed_callback):
    _set = e.set
    _clear = e.clear

    def or_set():
        _set()
        changed_callback()

    def or_clear():
        _clear()
        changed_callback()
    e.set = or_set
    e.clear = or_clear


def OrEvent(*events):
    or_event = threading.Event()

    def changed():
        bools = [e.is_set() for e in events]
        if any(bools):
            or_event.set()
        else:
            or_event.clear()
    for e in events:
        orify(e, changed)
    changed()
    return or_event


class EventTimer(Thread):
    """Call a function after a specified number of seconds.


    Examples:
        exit_event = Event()
        t = Timer(30.0, f, exit_event, args=None, kwargs=None)
        t.start()
        # either cancel by:
        t.cancel()
        # or
        exit_event.set()
    """

    def __init__(
        self,
        interval: float,
        function: Callable,
        exit_event: Event,
        args=None,
        kwargs=None
    ):
        Thread.__init__(self)
        self.interval = interval
        self.function = function
        self.args = args if args is not None else []
        self.kwargs = kwargs if kwargs is not None else {}
        self.finished = Event()
        self.exit_or_finished = OrEvent(exit_event, self.finished)

    def cancel(self):
        """Stop the timer if it hasn't finished yet."""
        self.finished.set()

    def run(self):
        self.exit_or_finished.wait(self.interval)
        if not self.exit_or_finished.is_set():
            self.function(*self.args, **self.kwargs)
        self.finished.set()


class EventThread(Thread):
    def __init__(
        self,
        function: Callable,
        exit_event: Event,
        args=None,
        kwargs=None
    ):
        Thread.__init__(self)
        self.function = function
        self.args = args if args is not None else []
        self.kwargs = kwargs if kwargs is not None else {}
        self.finished = Event()
        self.exit_or_finished = OrEvent(exit_event, self.finished)

    def stop(self):
        """Stop by triggering event passed to callback."""
        self.finished.set()

    def run(self):
        if not self.exit_or_finished.is_set():
            self.function(self.exit_or_finished, *self.args, **self.kwargs)
        self.finished.set()


def gen_pill():
    """Add stop method to Thread.

    Examples:
        pill, add_pill = gen_pill()
        t = threading.Thread(target=f, args=(pill,))
        add_pill(t)
        t.start()
        ...
        t.stop()
    """
    pill2kill = threading.Event()

    def stop():
        pill2kill.set()

    def add_pill(t: threading.Thread):
        t.stop = stop
    return pill2kill, add_pill
