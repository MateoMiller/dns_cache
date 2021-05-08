from records.record import Record


class PTRRecord(Record):
    def __init__(self, ttl, name):
        super().__init__(ttl)
        self.name = name
