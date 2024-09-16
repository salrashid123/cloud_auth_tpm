from tpm2_pytss import ESAPI
from abc import ABCMeta, abstractmethod


class PolicyEval(object, metaclass=ABCMeta):

    @abstractmethod
    def __init__(self, policy: dict[str, any], debug: bool):
        self._policy = policy
        self._debug = debug

    @abstractmethod
    def policy_callback(self, ectx: ESAPI):
        pass
