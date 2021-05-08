from records.record import Record


class NSRecord(Record):
    def __init__(self, ttl):
        super().__init__(ttl)
        self.servers = []