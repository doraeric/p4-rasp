from collections.abc import Callable
import queue
import threading
from threading import Thread

from p4.v1 import p4runtime_pb2
from p4runtime_sh.shell import P4Objects
from p4runtime_sh.context import P4Type
from p4runtime_sh.p4runtime import P4RuntimeClient

class PacketIn():
    """Modified PacketIn from p4runtime_sh.shell"""
    def __init__(self, client: P4RuntimeClient):
        self.client = client
        ctrl_pkt_md = P4Objects(P4Type.controller_packet_metadata)
        self.md_info_list = {}
        self.pill2kill = threading.Event()
        self.callback = None
        if "packet_in" in ctrl_pkt_md:
            self.p4_info = ctrl_pkt_md["packet_in"]
            for md_info in self.p4_info.metadata:
                self.md_info_list[md_info.name] = md_info

    def on_packet_in(
        self,
        callback: Callable[[p4runtime_pb2.PacketIn], None],
    ) -> None:
        """Decorator for packet-in event handler.

        Examples:
            @packet_in.on_packet_in
            def handler(packet):
                print(packet)
        """
        self.callback = callback

    def recv_bg(self):
        """Run callback function in another thread.

        Stop by either `p4runtime_sh.shell.teardown()` or `self.stop()`
        """
        def _packet_in_recv_func():
            while True:
                if self.pill2kill.is_set():
                    break
                try:
                    msg = self.client.stream_in_q['packet'].get(timeout=1)
                    if msg is None:
                        break
                    if self.callback is not None:
                        self.callback(msg.packet)
                except queue.Empty:
                    continue

        self.recv_t = Thread(target=_packet_in_recv_func)
        self.recv_t.start()

    def stop(self):
        """Stop receiving packets in background."""
        self.pill2kill.set()

