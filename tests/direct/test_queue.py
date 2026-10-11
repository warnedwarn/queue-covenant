from conftest import CONTRACT
import json


RULE = 'https://rules.example/queue'
RECORDS = ['https://records.example/a', 'https://records.example/b', 'https://records.example/c']


def opened(vm, deploy, owner):
    vm.strict_mocks = True
    vm.check_pickling = True
    vm.sender = owner
    contract = deploy(CONTRACT)
    contract.open_audit('q-17', 'Housing repair service queue', RULE, RECORDS)
    return contract


def sources(vm):
    vm.mock_web(r'rules\.example', {'status': 200, 'body': 'Rank 0 emergency, rank 1 accessibility, rank 2 standard. Earlier receipt wins ties.'})
    vm.mock_web(r'/a$', {'status': 200, 'body': 'Emergency. Received 100. Served 500.'})
    vm.mock_web(r'/b$', {'status': 200, 'body': 'Accessibility. Received 110. Served 300.'})
    vm.mock_web(r'/c$', {'status': 200, 'body': 'Standard. Received 120. Served 600.'})


def llm(vm, rows):
    vm.mock_llm(r'.*QueueCovenant extraction.*', json.dumps({'rows': rows}))


def rows(served=(500, 300, 600)):
    return [
        {'index': 0, 'status': 'OK', 'priority_rank': 0, 'received_at': 100, 'served_at': served[0]},
        {'index': 1, 'status': 'OK', 'priority_rank': 1, 'received_at': 110, 'served_at': served[1]},
        {'index': 2, 'status': 'OK', 'priority_rank': 2, 'received_at': 120, 'served_at': served[2]},
    ]


def test_detects_priority_inversion(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice)
    sources(direct_vm); llm(direct_vm, rows())
    contract.audit_queue('q-17')
    result = contract.get_audit('q-17')
    assert result['state'] == 'INVERSION'
    assert result['inversion_pairs'] == [[0, 1]]
    assert len(result['digests']) == 4


def test_fair_order(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice)
    sources(direct_vm); llm(direct_vm, rows((200, 300, 600)))
    contract.audit_queue('q-17')
    assert contract.get_audit('q-17')['state'] == 'FAIR'


def test_non_ok_record_is_inconclusive(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice)
    sources(direct_vm)
    data = rows(); data[2] = {'index': 2, 'status': 'MALFORMED', 'priority_rank': 0, 'received_at': 0, 'served_at': 0}
    llm(direct_vm, data); contract.audit_queue('q-17')
    assert contract.get_audit('q-17')['state'] == 'INCONCLUSIVE'


def test_validator_rejects_forged_source_digest(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice)
    sources(direct_vm); llm(direct_vm, rows())
    result = contract._extract(contract.audits['Q-17'])
    assert direct_vm.run_validator(leader_result=result) is True
    forged = {'digests': list(result['digests']), 'rows': result['rows']}
    forged['digests'][1] = '0' * 64
    assert direct_vm.run_validator(leader_result=forged) is False


def test_duplicate_slots_and_duplicate_id_rejected(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice)
    with direct_vm.expect_revert('unique audit id'):
        contract.open_audit('q-17', 'Duplicate queue', RULE, RECORDS)
    with direct_vm.expect_revert('distinct records'):
        contract.open_audit('q-18', 'Duplicate slots', RULE, [RECORDS[0], RECORDS[0], RECORDS[2]])


def test_cancel_authorization_and_replay(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = opened(direct_vm, direct_deploy, direct_alice)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert('owner of open audit'):
        contract.cancel_open('q-17')
    direct_vm.sender = direct_alice
    contract.cancel_open('q-17')
    with direct_vm.expect_revert('open audit required'):
        contract.audit_queue('q-17')
