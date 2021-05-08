import math
import time


class Record:
    def __init__(self, ttl):
        self._init_time = time.time()
        self.ttl = ttl

    def is_expired(self):
        return self.remain_ttl() == 0

    def remain_ttl(self):
        passed_time = int(time.time() - self._init_time)
        return max(0, self.ttl - passed_time)
