"""Offline public contract schema checks; requires the scripts JSON Schema dependency."""
from __future__ import annotations

import copy
import itertools
import json
import re
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / 'artifacts/openapi/torii.json'


class PublicContractSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads(SPEC.read_text())
        cls.schemas = cls.spec['components']['schemas']

    def validator(self, name):
        return Draft202012Validator({'$ref': '#/components/schemas/' + name, 'components': self.spec['components']})

    def draft_request(self):
        return {'authority': 'canonical-authority', 'contract_alias': 'router::universal',
                'entrypoint': 'ping', 'metadata': {'business_note': 'exact'},
                'fee_payment': {'payer': 'authority', 'value': {'charge_limits': [], 'gas_limit': 5000}}}

    def response(self, submitted):
        tx_hash = 'a' * 63 + '1' if submitted else None
        receipt = dict(operation_kind='contract_call', status='submitted' if submitted else 'pending_signature',
                       transport='torii', dataspace='universal', contract_alias='router::universal',
                       contract_address='canonical-contract-address', code_hash_hex='a' * 64, abi_hash_hex='b' * 64,
                       tx_hash_hex=tx_hash, entrypoint='ping', entrypoint_hash_hex=tx_hash,
                       gas_limit=5000, gas_used=None, fee_payment=self.draft_request()['fee_payment'],
                       payload_digest_hex='c' * 64)
        return dict(ok=True, submitted=submitted, dataspace='universal', contract_address=receipt['contract_address'],
                    code_hash_hex=receipt['code_hash_hex'], abi_hash_hex=receipt['abi_hash_hex'], creation_time_ms=42,
                    transaction_ttl_ms=None, tx_hash_hex=tx_hash, pipeline_status=None, entrypoint_hash_hex=tx_hash,
                    transaction_payload_b64=None if submitted else 'AQ==',
                    signing_message_b64=None if submitted else 'Ag==', entrypoint='ping', operation_receipt=receipt)

    def test_all_three_authored_spec_copies_are_identical(self):
        self.assertEqual(SPEC.read_bytes(), (ROOT / 'crates/iroha_torii/assets/openapi/torii.json').read_bytes())
        self.assertEqual(SPEC.read_bytes(), (ROOT / 'artifacts/openapi/versions/current/torii.json').read_bytes())

    def test_ram_execute_cannot_claim_a_plaintext_opening(self):
        payload = dict(program_id='example', program_digest='a' * 64,
                       backend='bfv-programmed-v1', verification_mode='signed',
                       input_ciphertext_hash='b' * 64, output_ciphertext_hash='c' * 64,
                       parameter_digest='d' * 64, evaluation_key_digest='e' * 64,
                       output_hash='c' * 64, associated_data_hash='f' * 64,
                       executed_at_ms=42)
        receipt = dict(payload=payload, attestation=dict(kind='signed', signature='aa' * 64))
        response = dict(program_id='example', program_id_canonical='ABCD',
                        opaque_hash='a' * 64, receipt_hash='b' * 64, opaque_output='ABCD',
                        output_hash='c' * 64, associated_data_hash='f' * 64,
                        executed_at_ms=42, backend='bfv-programmed-v1',
                        verification_mode='signed', receipt=receipt)
        validator = self.validator('RamLfeExecuteResponse')
        self.assertTrue(validator.is_valid(response))
        for field in ['program_id_canonical', 'opaque_output']:
            incomplete = response.copy()
            del incomplete[field]
            self.assertFalse(validator.is_valid(incomplete))
            self.assertFalse(validator.is_valid(response | {field: None}))
            self.assertFalse(validator.is_valid(response | {field: 'abc'}))
        self.assertFalse(validator.is_valid(response | {'program_id_canonical': 'AA' * 4097}))
        self.assertFalse(validator.is_valid(response | {'output_ciphertext': 'ABCD'}))
        for opening in [None, {}, dict(payload=payload, signature='aa' * 64)]:
            self.assertFalse(validator.is_valid(response | {'output_opening': opening}))
        source = (ROOT / 'crates/iroha_torii/src/routing.rs').read_text()
        body = re.search(r'pub struct RamLfeExecuteResponseDto \{(.*?)\n\}', source, re.S).group(1)
        self.assertEqual(set(re.findall(r'pub (\w+):', body)),
                         set(self.schemas['RamLfeExecuteResponse']['properties']))
        self.assertIn('RamLfeOutputOpening', self.schemas)

    def test_detached_fields_are_one_complete_non_null_group(self):
        v = self.validator('ContractCallRequest')
        fields = {'public_key_hex': 'a' * 64, 'signature_b64': 'AQ==', 'transaction_payload_b64': 'Ag=='}
        for present in itertools.product([False, True], repeat=3):
            request = self.draft_request() | {k: value for (k, value), use in zip(fields.items(), present) if use}
            if all(present): request['creation_time_ms'] = 42
            self.assertEqual(v.is_valid(request), all(present) or not any(present), present)
        request = self.draft_request() | fields
        self.assertFalse(v.is_valid(request))
        request['creation_time_ms'] = None
        self.assertFalse(v.is_valid(request))
        self.assertTrue(v.is_valid(self.draft_request() | {k: None for k in fields}))
        for key in fields:
            self.assertFalse(v.is_valid(self.draft_request() | fields | {key: None, 'creation_time_ms': 42}))

    def test_request_rejects_private_unknown_reserved_metadata_and_null_gas(self):
        v = self.validator('ContractCallRequest')
        for field in ['private_key', 'privateKey', 'admission_intent', 'unexpected']:
            self.assertFalse(v.is_valid(self.draft_request() | {field: 'not-a-secret'}), field)
        for key in ['contract_address', 'validation_fee_any', 'fee_sponsor', 'fee_sponsor_account', 'gas_asset_id', 'gas_limit']:
            self.assertFalse(v.is_valid(self.draft_request() | {'metadata': {key: 'x'}}), key)
        for gas in [None, 0, -1, 2**64]:
            request = self.draft_request(); request['fee_payment']['value']['gas_limit'] = gas
            self.assertFalse(v.is_valid(request), gas)

    def test_target_exclusivity_and_optional_default_ttl_selection(self):
        v = self.validator('ContractCallRequest')
        for ttl in [None, 1, 100000]: self.assertTrue(v.is_valid(self.draft_request() | {'transaction_ttl_ms': ttl}))
        for ttl in [0, -1, 2**64]: self.assertFalse(v.is_valid(self.draft_request() | {'transaction_ttl_ms': ttl}))
        self.assertTrue(v.is_valid(self.draft_request() | {'contract_address': None}))
        self.assertFalse(v.is_valid(self.draft_request() | {'contract_address': 'another-address'}))
        self.assertFalse(v.is_valid(self.draft_request() | {'contract_alias': None}))
        description = self.schemas['ContractCallResponse']['properties']['transaction_ttl_ms']['description']
        self.assertIn('100000ms', description)
        self.assertIn('does not mean an unbounded payload', description)

    def test_success_shapes_are_closed_complete_and_never_fabricate_pipeline_state(self):
        v = self.validator('ContractCallResponse')
        for submitted in [False, True]:
            good = self.response(submitted); self.assertTrue(v.is_valid(good))
            for key in good:
                mutated = copy.deepcopy(good); del mutated[key]
                self.assertFalse(v.is_valid(mutated), key)
            for key in good['operation_receipt']:
                mutated = copy.deepcopy(good); del mutated['operation_receipt'][key]
                self.assertFalse(v.is_valid(mutated), key)
            for mutation in [{'pipeline_status': {'status': {'kind': 'Queued'}}}, {'unexpected': None}]:
                self.assertFalse(v.is_valid(good | mutation))
            mutated = copy.deepcopy(good); mutated['operation_receipt']['gas_used'] = 1
            self.assertFalse(v.is_valid(mutated))
            mutated = copy.deepcopy(good); mutated['operation_receipt']['status'] = 'pending_signature' if submitted else 'submitted'
            self.assertFalse(v.is_valid(mutated))
            self.assertFalse(v.is_valid(good | {'submitted': not submitted}))

    def test_operation_retains_canonical_auth_and_exact_prepare_submit_contract(self):
        operation = self.spec['paths']['/v1/contracts/call']['post']
        self.assertEqual(operation['responses']['200']['content']['application/json']['schema']['$ref'], '#/components/schemas/ContractCallResponse')
        self.assertEqual(operation['x-iroha-route-auth']['authentication'], 'canonical_account_signature')
        self.assertEqual(set(operation['security'][0]), {'IrohaCanonicalAccount', 'IrohaCanonicalNonce', 'IrohaCanonicalSignature', 'IrohaCanonicalTimestampMs'})
        for phrase in ['Ordinary admission', 'one actual resolved route', 'never re-quoted',
                       'durable single-route queue admission', 'Applied finality',
                       'multi-route work is rejected before any durable pending promise']:
            self.assertIn(phrase, operation['description'])
        for retired in ['QueuePlanSynced', 'durable certified admission']:
            self.assertNotIn(retired, operation['description'])
        self.assertIn('503', operation['responses'])

    def test_schema_fields_follow_the_actual_rust_dtos(self):
        source = (ROOT / 'crates/iroha_torii/src/routing.rs').read_text()
        for dto, schema in [('ContractCallDto', 'ContractCallRequest'), ('ContractCallResponseDto', 'ContractCallResponse'), ('OperationReceiptDto', 'ContractCallOperationReceipt')]:
            body = re.search(r'pub struct ' + dto + r' \{(.*?)\n\}', source, re.S).group(1)
            fields = re.findall(r'pub (\w+):', body)
            self.assertEqual(set(fields), set(self.schemas[schema]['properties']))
            if dto != 'ContractCallDto':
                self.assertEqual(set(fields), set(self.schemas[schema]['required']))
                self.assertNotIn('skip_serializing_if', body)


if __name__ == '__main__':
    unittest.main()
