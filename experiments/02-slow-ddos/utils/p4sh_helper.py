from collections.abc import Callable
from dataclasses import dataclass
from functools import cache, partial
from operator import attrgetter
import queue
import threading
from threading import Thread
from typing import Literal

from google.protobuf import text_format
from p4.config.v1 import p4info_pb2
from p4.v1 import p4runtime_pb2
import p4runtime_sh
from p4runtime_sh import bytes_utils
import p4runtime_sh.shell as sh
from p4runtime_sh.shell import P4Objects
from p4runtime_sh.context import P4Type
from p4runtime_sh.p4runtime import P4RuntimeClient


def _get_preamble_types() -> dict[str, str]:
    d = p4info_pb2.P4Info.DESCRIPTOR
    types = {}
    for f in d.fields:
        if f.label != f.LABEL_REPEATED:
            continue
        if not any(i.name == "preamble" for i in f.message_type.fields):
            continue
        types[f.message_type.name] = f.name
    return types


_entity_fields = {
    i.message_type.name: i.name for i in p4runtime_pb2.Entity.DESCRIPTOR.fields
}
_preamble_types = _get_preamble_types()


class P4Info:
    @classmethod
    def read_txt(cls, path: str):
        pb = text_format.Parse(open(path).read(), p4info_pb2.P4Info())
        return cls(pb)

    def __init__(self, pb: p4info_pb2.P4Info):
        self.pb = pb
        self.preamble_ids = {}
        self.preamble_names = {}
        for ftype, fname in _preamble_types.items():
            self.preamble_ids[ftype] = {}
            self.preamble_names[ftype] = {}
            repeated = getattr(pb, fname, None)
            if repeated is None:
                continue
            for p4info_field in repeated:
                preamble = p4info_field.preamble
                self.preamble_ids[ftype][preamble.name] = preamble.id
                self.preamble_names[ftype][preamble.id] = preamble.name
        self.DigestEntry = partial(DigestEntry, p4info=self)

    def get_digest_id(self, name: str) -> int:
        return self.preamble_ids['Digest'].get(name)

    def get_digest_name(self, digest_id: int) -> str:
        return self.preamble_names['Digest'].get(digest_id)

    @cache
    def get_member_names(self, name: str | int) -> list[str]:
        if not isinstance(name, (str, int)):
            raise TypeError('`name` must be either str or int')
        if isinstance(name, int):
            for names in self.preamble_names.values():
                name = names.get(name, name)
                if isinstance(name, str):
                    break
            if isinstance(name, int):
                raise KeyError(f'preamble id {name} not found')
        struct_types = self.pb.type_info.structs.keys()
        if name not in struct_types:
            raise KeyError(f'struct type "{name}" not found')
        names = [i.name for i in self.pb.type_info.structs[name].members]
        return names


class UpdateEntity:
    def as_entity(self) -> p4runtime_pb2.Entity:
        pb = self.pb
        field_name = _entity_fields[type(pb).__name__]
        entity = p4runtime_pb2.Entity()
        getattr(entity, field_name).CopyFrom(pb)
        return entity

    def as_update(self, method='insert') -> p4runtime_pb2.Update:
        """Convert to p4.v1.Update protobuf message.

        Args:
            method: 'insert' | 'modify' | 'delete'
        """
        update = p4runtime_pb2.Update()
        method = method.lower()
        if method == 'insert':
            _type = p4runtime_pb2.Update.INSERT
        elif method == 'modify':
            _type = p4runtime_pb2.Update.MODIFY
        elif method == 'delete':
            _type = p4runtime_pb2.Update.DELETE
        else:
            _type = p4runtime_pb2.Update.UNSPECIFIED
        update.type = _type
        pb = self.pb
        field_name = _entity_fields[type(pb).__name__]
        getattr(update.entity, field_name).CopyFrom(pb)
        return update


@dataclass
class DigestEntry(UpdateEntity):
    name: str = property(attrgetter("_name"))
    digest_id: int = property(attrgetter("_digest_id"))
    max_timeout_ns: int = 0
    max_list_size: int = 1
    ack_timeout_ns: int = 0
    p4info: P4Info = None

    def __init__(
        self,
        name: str = None,
        digest_id: int = None,
        **kwargs,
    ):
        for key, value in kwargs.items():
            setattr(self, key, value)
        if name is not None and digest_id is not None:
            raise ValueError(
                'Setting both arguments `name` and `digest_id` is not allowed')
        if name is None and digest_id is None:
            raise ValueError('Missing argument `name` or `digest_id`')
        if not isinstance(name, (str, int)):
            raise TypeError(
                'First argument `name` should be either str or int as id')
        if isinstance(name, int):
            digest_id = name
            name = None
        if digest_id is None and self.p4info is None:
            raise ValueError('Need `p4info` to generate DigestEntry from name')
        if name is not None:
            self._name = name
            self._digest_id = self.p4info.get_digest_id(name)
            if self._digest_id is None:
                raise KeyError(f'Digest with name="{name}" not found')
        else:
            self._name = name
            self._digest_id = digest_id

    @property
    def pb(self) -> p4runtime_pb2.DigestEntry:
        pb = p4runtime_pb2.DigestEntry()
        pb.digest_id = self.digest_id
        pb.config.max_timeout_ns = self.max_timeout_ns
        pb.config.max_list_size = self.max_list_size
        pb.config.ack_timeout_ns = self.ack_timeout_ns
        return pb


class StreamClient:
    """Modified PacketIn from p4runtime_sh.shell"""
    def __init__(self, client: P4RuntimeClient):
        self.client = client
        ctrl_pkt_md = P4Objects(P4Type.controller_packet_metadata)
        self.md_info_list = {}
        self.pill2kill = threading.Event()
        self.packet_in_callback = None
        self.digest_list_callback = None
        if "packet_in" in ctrl_pkt_md:
            self.p4_info = ctrl_pkt_md["packet_in"]
            for md_info in self.p4_info.metadata:
                self.md_info_list[md_info.name] = md_info

    def on(self, msg_type: Literal['packet', 'digest']):
        if msg_type == 'packet':
            return self.on_packet_in
        if msg_type == 'digest':
            return self.on_digest_list

    def on_packet_in(
        self,
        callback: Callable[[p4runtime_pb2.PacketIn], None],
    ) -> None:
        """Decorator for packet-in event handler.

        Examples:
            @stream_client.on_packet_in
            def handler(packet):
                print(packet)
        """
        self.packet_in_callback = callback
    on_packet = on_packet_in

    def on_digest_list(
        self,
        callback: Callable[[p4runtime_pb2.DigestEntry], None],
    ) -> None:
        self.digest_list_callback = callback
    on_digest = on_digest_list

    def get_callback(self, msg_type):
        if msg_type == 'packet':
            return self.packet_in_callback
        if msg_type == 'digest':
            return self.digest_list_callback
        return None

    def recv_bg(self):
        """Run callback function in another thread.

        Stop by either `p4runtime_sh.shell.teardown()` or `self.stop()`
        """
        def _stream_handler(msg_type: str):
            """
            Args:
                msg_type: "arbitration" | "packet" | "digest" | "unknown"
            """
            while True:
                if self.pill2kill.is_set():
                    break
                try:
                    msg = self.client.stream_in_q[msg_type].get(timeout=1)
                    if msg is None:
                        break
                    cb = self.get_callback(msg_type)
                    if cb is not None:
                        cb(getattr(msg, msg_type))
                except queue.Empty:
                    continue

        self.recv_packet_t = Thread(target=_stream_handler, args=('packet',))
        self.recv_packet_t.start()
        self.recv_digest_t = Thread(target=_stream_handler, args=('digest',))
        self.recv_digest_t.start()

    def stop(self):
        """Stop receiving packets in background."""
        self.pill2kill.set()


class TableEntry(sh.TableEntry):
    def __init__(self, table_name=None):
        super().__init__(table_name)
        self.match = MatchKeyBin(table_name, self._info.match_fields)

    def __call__(self, **kwargs):
        for name, value in kwargs.items():
            if name == "action" and type(value) is str:
                value = Action(value)
            setattr(self, name, value)
        return self


class MatchKeyBin(sh.MatchKey):
    """MatchKey that is able to assign bytes value directly."""
    def __setitem__(self, name: str, value: str | bytes):
        field_info = self._get_mf(name)
        if isinstance(value, str):
            self._mk[name] = self._parse_mf(value, field_info)
        elif isinstance(value, bytes):
            self._mk[name] = self._parse_mf_bin(value, field_info)
        else:
            raise TypeError('`value` should be either str or bytes')

    def _parse_mf_bin(self, value: bytes, field_info):
        if field_info.match_type == p4info_pb2.MatchField.EXACT:
            return self._sanitize_and_convert_mf_exact(value, field_info)
        elif field_info.match_type == p4info_pb2.MatchField.LPM:
            raise NotImplementedError
        elif field_info.match_type == p4info_pb2.MatchField.TERNARY:
            # FIXME: no tuple from __setitem__
            if isinstance(value, tuple) and len(value) == 2:
                return self._sanitize_and_convert_mf_ternary(
                    *value, field_info)
            if isinstance(value, bytes):
                bitwidth = field_info.bitwidth
                mask = bytes_utils.parse_value('0b' + '1' * bitwidth, bitwidth)
                return self._sanitize_and_convert_mf_ternary(
                    value, mask, field_info)
            raise NotImplementedError
        elif field_info.match_type == p4info_pb2.MatchField.RANGE:
            raise NotImplementedError
        elif field_info.match_type == p4info_pb2.MatchField.OPTIONAL:
            raise NotImplementedError
        else:
            raise p4runtime_sh.utils.UserError(
                f"Unsupported match type for field:\n{field_info}")


class Action(sh.Action):
    """Quiet version Action"""
    def __setitem__(self, name, value):
        param_info = self._get_param(name)
        self._param_values[name] = self._parse_param(value, param_info)
