from typing import Optional

from records.aRecord import ARecord
from records.aaaaRecord import AAAARecord
from records.nsRecord import NSRecord
from records.ptrRecord import PTRRecord


class RecordsContainer:
    def __init__(self):
        self.a: Optional[ARecord] = None
        self.aaaa: Optional[AAAARecord] = None
        self.ns: Optional[NSRecord] = None
        self.ptr: Optional[PTRRecord] = None

    def delete_expired_records(self):
        if self.a is not None and self.a.is_expired():
            self.a = None
        if self.aaaa is not None and self.aaaa.is_expired():
            self.aaaa = None
        if self.ns is not None and self.ns.is_expired():
            self.ns = None
        if self.ptr is not None and self.ptr.is_expired():
            self.ptr = None

    def is_empty(self):
        #Содержит хотя бы одну запись
        return not any([self.a, self.aaaa, self.ptr, self.ns])
