from forta_agent import FindingSeverity, FindingType, create_transaction_event, get_web3_provider
from web3 import contract
from web3 import Web3
from web3.types import ABIFunction
from constants import MAXIMUM_CALLERS_ALLOWED, APPROVE_FUNCTION_ABI
from agent import handle_transaction

class TestPhishingAttackAgent:
    def test_returns_empty_findings_if_low_number_of_callers(self):
        findings = self.make_approving_transactions(MAXIMUM_CALLERS_ALLOWED - 1)

        assert len(findings) == 0

    def test_returns_finding_if_high_number_of_callers(self):
        findings = self.make_approving_transactions(MAXIMUM_CALLERS_ALLOWED + 1)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.name == "Possible phishing attack"
        assert finding.description == f'Affected address: receiver_address'
        assert finding.alert_id == 'FORTA-1'
        assert finding.type == FindingType.Suspicious
        assert finding.severity == FindingSeverity.Info
        assert finding.metadata['attackers address'] == [
            ('caller_address' + i) for i in range(MAXIMUM_CALLERS_ALLOWED + 1)]

    def make_approving_transactions(self, transactions_amount: int):
        receiver = '0xA1E4380A3B1f749673E270229993eE55F35663c4'
        callers = []

        # create (transactions_amount) callers
        for i in range(transactions_amount):
            callers.append('0xA1E4380A3B1f749673E270229993eE55F35663b' + str(i))

        def approve():
            pass

        findings = []
        for caller in callers:
            tx_event = create_transaction_event(
                {'transaction': 
                    {'from_': caller,
                    'to': receiver},
                    'traces':
                    [{
                        'action': 
                        {
                            'to': receiver,
                            'input': (approve, {}) # TODO: Encode input
                        }
                    }],
                    'block': { 'timestamp': 1 }
                })

            findings += handle_transaction(tx_event)

        return findings