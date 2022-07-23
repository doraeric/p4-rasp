import threading


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
