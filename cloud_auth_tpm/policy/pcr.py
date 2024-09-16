from tpm2_pytss import *
from cloud_auth_tpm.policy.policy import PolicyEval


class PCRPolicy(PolicyEval):

    DEFAULT_POLICY = {
        "description": "Default Policy",
        "policy": [
            {
                "type": "POLICYPCR",
                "pcrs": []
            }
        ]
    }

    def __init__(
        self,
        policy=None,
        debug=False
    ):

        super().__init__(policy=policy, debug=debug)
        # self._debug = debug
        # self._policy = policy or self.DEFAULT_POLICY

    def _pcr_cb(self, selection):
        sel = TPMS_PCR_SELECTION(
            hash=TPM2_ALG.SHA256,
            sizeofSelect=selection.selections.pcr_select.sizeofSelect,
            pcrSelect=selection.selections.pcr_select.pcrSelect,
        )
        out_sel = TPML_PCR_SELECTION((sel,))
        digests = list()
        selb = bytes(sel.pcrSelect[0: sel.sizeofSelect])
        seli = int.from_bytes(reversed(selb), "big")
        for i in range(0, sel.sizeofSelect * 8):
            if (1 << i) & seli:
                dig = TPM2B_DIGEST(bytes([i]) * 32)
                digests.append(dig)
        out_dig = TPML_DIGEST(digests)
        return (out_sel, out_dig)

    def policy_callback(self, ectx):
        sess = ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            auth_hash=TPM2_ALG.SHA256,
        )
        polstr = json.dumps(self._policy).encode()
        with policy(polstr, TPM2_ALG.SHA256) as p:
            p.set_callback(policy_cb_types.CALC_PCR, self._pcr_cb)
            p.calculate()
            if self._debug:
                cjb = p.get_calculated_json()
                json_object = json.loads(cjb)
                print(json.dumps(json_object, indent=4))
            p.execute(ectx, sess)
        return sess
