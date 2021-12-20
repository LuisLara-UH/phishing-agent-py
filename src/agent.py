from forta_agent import Finding, FindingType, FindingSeverity, TransactionEvent
from owned_address import OwnedAddress
from constants import ERC_20_TRANSFER_FROM_FUNCTION_ABI


findings_count = 0

owned_addresses = {}


def handle_transaction(transaction_event: TransactionEvent):
    findings = []
    
    global findings_count
    if findings_count >= 10:
        # Maximum number of alerts set to 10 to avoid spamming
        return findings

    # get targeted address
    targeted_address = transaction_event.to
    ####

    try:
        owned_addresses[targeted_address]
    except KeyError:
        owned_addresses[targeted_address] = OwnedAddress(targeted_address)

    address: OwnedAddress = owned_addresses[targeted_address]

    # find if transaction calls approve() or increaseAllowance()
    transfer_from_invocations = transaction_event.filter_function(ERC_20_TRANSFER_FROM_FUNCTION_ABI)
    is_approving_transaction = False
    ###

    # get timestamp of block and caller address
    timestamp = 0
    caller_address = ''
    ###

    if is_approving_transaction:
        address.receive_call(caller_address, timestamp)

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
