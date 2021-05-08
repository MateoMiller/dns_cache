from records.record import Record


class ARecord(Record):
    def __init__(self, ttl):
        super().__init__(ttl)
        self.addresses = []