from forta_agent import Finding, FindingType, FindingSeverity, TransactionEvent
from owned_address import OwnedAddress
from constants import APPROVE_FUNCTION_ABI, INCREASE_ALLOWANCE_FUNCTION_ABI
import pdb


findings_count = 0

owned_addresses = {}


def handle_transaction(transaction_event: TransactionEvent):
    findings = []
    global findings_count
    if findings_count >= 10:
        # Maximum number of alerts set to 10 to avoid spamming
        return findings

    # save targeted address
    targeted_address = transaction_event.to

    try:
        owned_addresses[targeted_address]
    except KeyError:
        owned_addresses[targeted_address] = OwnedAddress(targeted_address)

    address: OwnedAddress = owned_addresses[targeted_address]

    # find if transaction calls approve() or increaseAllowance()
    transfer_from_invocations = transaction_event.filter_function(APPROVE_FUNCTION_ABI)
    transfer_from_invocations += transaction_event.filter_function(INCREASE_ALLOWANCE_FUNCTION_ABI)
    
    is_approving_transaction = False
    for invocation in transfer_from_invocations:
        transaction_function = invocation[0]
        function_name = transaction_function.__name__
        if function_name == 'approve' or function_name == 'increaseAllowance':
            is_approving_transaction = True
    
    # get timestamp of block and caller address
    timestamp = transaction_event.timestamp
    caller_address = transaction_event.from_
    # 

    if is_approving_transaction:
        print('is approving')
        address.receive_call(caller_address, timestamp)
        print('call received')

        if address.possible_attack():
            findings.append(Finding({
                'name': 'Possible phishing attack',
                'description': f'Affected address: ' + targeted_address,
                'alert_id': 'FORTA-1',
                'type': FindingType.Suspicious,
                'severity': FindingSeverity.Info,
                'metadata': {
                    'attackers address': address.get_callers(),
                    'amounts of tokens': ''
                }
            }))
            findings_count += 1
    return findings
