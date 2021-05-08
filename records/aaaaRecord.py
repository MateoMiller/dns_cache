from records.record import Record


class AAAARecord(Record):
    def __init__(self, ttl):
        super().__init__(ttl)
        self.addresses = []