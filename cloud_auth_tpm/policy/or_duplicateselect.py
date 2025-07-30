from tpm2_pytss import *

from cloud_auth_tpm.policy.policy import PolicyEval

class PolicyORAndDuplicateSelectPolicy(PolicyEval):

    def __init__(
        self,
        policy=None,
        debug=False,
    ):

        super().__init__(policy=policy, debug=debug)
        # self._debug = debug

    def _auth_duplicate_cb(self, auth_object, branches):
        if self._debug:
            print(auth_object)
            print(branches)
        return 0

    def policy_callback(self, ectx: ESAPI, handle: ESYS_TR):
        sess = ectx.start_auth_session(
            tpm_key=handle, #ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=TPMT_SYM_DEF(
              algorithm=TPM2_ALG.AES,
              keyBits=TPMU_SYM_KEY_BITS(sym=128),
              mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
            ),
            auth_hash=TPM2_ALG.SHA256,
        )        
        polstr = json.dumps(self._policy).encode()
        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.EXEC_POLSEL, self._auth_duplicate_cb)
            p.calculate()
            if self._debug:
                cjb = p.get_calculated_json()
                json_object = json.loads(cjb)
                print(json.dumps(json_object, indent=4))
            p.execute(ectx, sess)

        ectx.trsess_set_attributes(
            sess, ( TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        )
        return sess
