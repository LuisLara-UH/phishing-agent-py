import constants

class OwnedAddress:
    def __init__(self, address) -> None:
        self.address = address

        # caller's address -> timestamp of call
        self.callers = {}

    def get_callers(self):
        return self.callers.keys()

    def receive_call(self, caller_address, timestamp: int):
        self.callers[caller_address] = timestamp
        self.clear_old_calls(timestamp)

    # clear old calls(those with timestamp < 24 hours ago)
    def clear_old_calls(self, actual_timestamp: int):
        dict_keys = [key for key in self.callers.keys()]
        for key in dict_keys:
            if self.callers[key] < actual_timestamp - constants.ONE_DAY_SECONDS:
                self.callers.pop(key)

    def possible_attack(self) -> bool:
        return len(self.callers.keys()) > 10