"""Authored OpenAPI contracts of the native ledger scoped-original reads.

The reads are `/v1/ledger/resource-names/{challenge}` and
`/v1/ledger/authority-originals`. These tests check their catalog entries,
media limits and exact JSON shapes, and validate public synthetic native output
against the shared finality, World snapshot and asset-definition schemas. They
provide no account, signature, World-root, finality, proof, native startup or
release qualification.
"""

import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
MIRRORS = (
    ROOT / 'artifacts/openapi/torii.json',
    ROOT / 'crates/iroha_torii/assets/openapi/torii.json',
    ROOT / 'artifacts/openapi/versions/current/torii.json',
)
SHAPES = Path(__file__).parent / 'fixtures/ledger_scoped_original_shapes_v1.json'
READS = (
    ('/v1/ledger/resource-names/{challenge}', 'get', 'ledger.resource_names_state', None, 128 * 1024 * 1024, 'NativeResourceNamesStateV1'),
    ('/v1/ledger/authority-originals', 'post', 'ledger.authority_originals', 64 * 1024, 128 * 1024 * 1024, 'NativeAuthorityOriginalsV1'),
)
RESPONSE_ROOTS = tuple(read[-1] for read in READS)
SECURITY = [
    {'IrohaCanonicalAccount': [], 'IrohaCanonicalNonce': [], 'IrohaCanonicalSignature': [], 'IrohaCanonicalTimestampMs': []},
    {'IrohaCanonicalWitness': []},
]
NESTED_SHAPES = (
    ('attestation', ()),
    ('attestation', ('body',)),
    ('attestation', ('body', 'status')),
    ('world_snapshot', ()),
    ('asset_definition', ()),
    ('asset_definition', ('spec',)),
    ('asset_definition', ('confidential_policy',)),
)


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate member ' + key)
        result[key] = value
    return result


@pytest.fixture(scope='module')
def document():
    return json.loads(MIRRORS[0].read_bytes(), object_pairs_hook=reject_duplicates)


def validator(document, name):
    return Draft202012Validator({'$ref': '#/components/schemas/' + name, 'components': document['components']})


def asset_definition_schema(document):
    """Name the asset-definition component that the fee-program original embeds."""
    reference = document['components']['schemas']['NativeGlobalFeeProgramStateV1']['properties']['fee_asset_definition']['$ref']
    return reference.rsplit('/', 1)[1]


def descend(value, path):
    for key in path:
        value = value[key]
    return value


@pytest.fixture(scope='module')
def shape_data():
    shapes = json.loads(SHAPES.read_bytes(), object_pairs_hook=reject_duplicates)
    return {
        'attestation': shapes['attestation'], 'world_snapshot': shapes['world_snapshot'],
        'network_id': shapes['attestation']['body']['network_id'],
        'asset_definition': shapes['asset_definition'],
        'signatory': shapes['signatory'], 'wallet': shapes['wallet'],
    }


@pytest.mark.parametrize('path,method,stable_id,request_bound,response_bound,json_name', READS)
def test_ledger_reads_have_the_actual_catalog_and_signed_transport(document, path, method, stable_id, request_bound, response_bound, json_name):
    operation = document['paths'][path][method]
    catalog = (ROOT / 'crates/iroha_torii_shared/src/route_catalog.rs').read_text()
    block = catalog.split('"' + stable_id + '"', 1)[1].split('.with_cors_options(true)', 1)[0]
    assert '"' + path + '"' in block
    assert 'RouteEffect::ReadOnly' in block
    assert 'AdmissionPolicy::AuthenticatedAccount' in block
    assert 'AuthenticationPolicy::CanonicalAccountSignature' in block
    assert 'RouteProjections::OPENAPI_AND_SDK' in block
    assert operation['security'] == SECURITY
    assert operation['x-iroha-route-auth'] == {'admission': 'authenticated_account', 'authentication': 'canonical_account_signature', 'schemaVersion': 1, 'stableRouteId': stable_id}
    assert operation['x-iroha-tool-effect'] == 'read'
    assert operation['x-iroha-max-response-bytes'] == response_bound
    content = operation['responses']['200']['content']
    assert set(content) == {'application/json', 'application/x-norito'}
    assert content['application/x-norito']['schema']['maxLength'] == response_bound
    assert content['application/x-norito']['schema']['minLength'] == 1
    assert content['application/x-norito']['schema']['format'] == 'binary'
    assert content['application/x-norito']['schema']['x-iroha-norito-schema'] == operation['x-iroha-norito-response-type']
    assert content['application/json']['schema'] == {'$ref': '#/components/schemas/' + json_name}
    if request_bound is None:
        assert 'requestBody' not in operation
    else:
        assert operation['x-iroha-max-request-bytes'] == request_bound
        assert operation['requestBody']['required'] is True
        request = operation['requestBody']['content']
        assert set(request) == {'application/x-norito'}
        assert request['application/x-norito']['schema']['maxLength'] == request_bound
        assert request['application/x-norito']['schema']['x-iroha-norito-schema'] == operation['x-iroha-norito-request-type']


def test_authored_mirrors_and_native_schema_references_are_valid(document):
    assert all(path.read_bytes() == MIRRORS[0].read_bytes() for path in MIRRORS)
    schemas = document['components']['schemas']
    for name, value in schemas.items():
        if name.startswith('Native'):
            Draft202012Validator.check_schema(value)

    def references(value):
        if isinstance(value, dict):
            if '$ref' in value:
                assert value['$ref'].startswith('#/components/schemas/')
                assert value['$ref'].rsplit('/', 1)[1] in schemas
            for nested in value.values():
                references(nested)
        elif isinstance(value, list):
            for nested in value:
                references(nested)

    for path, method, *_ in READS:
        references(document['paths'][path][method])
    for name, value in schemas.items():
        if name.startswith('Native'):
            references(value)


@pytest.mark.parametrize('path,method,stable_id,request_bound,response_bound,json_name', READS)
def test_ledger_reads_keep_exact_private_outer_headers(document, path, method, stable_id, request_bound, response_bound, json_name):
    for response in document['paths'][path][method]['responses'].values():
        assert response['headers']['Cache-Control']['schema']['const'] == 'private, no-store'
        assert response['headers']['X-Content-Type-Options']['schema']['const'] == 'nosniff'
        assert response['headers']['Vary']['schema']['const'] == 'X-Iroha-Finality-Challenge, Accept'


@pytest.mark.parametrize('value', ['0' * 64, 'AB' * 32, 'ab' * 31, 'ab' * 33, 'ab' * 32 + ' ', '0x' + 'ab' * 32, 'gh' * 32])
def test_names_challenge_refuses_noncanonical_or_zero_http_spelling(document, value):
    operation = document['paths']['/v1/ledger/resource-names/{challenge}']['get']
    assert len(operation['parameters']) == 2
    for parameter in operation['parameters']:
        assert parameter['required'] is True
        check = Draft202012Validator(parameter['schema'])
        check.validate('ab' * 32)
        assert not check.is_valid(value)
    assert next(p for p in operation['parameters'] if p['in'] == 'header')['x-iroha-header-count'] == 1


@pytest.mark.parametrize('name', ['NativeNonzeroDigestV1', 'NativeSha256DigestV1'])
def test_fixed_byte_json_is_uppercase_hex_and_distinct_from_hash_literals(document, name):
    check = validator(document, name)
    check.validate('AB' * 32)
    assert check.is_valid('0' * 64) is (name == 'NativeSha256DigestV1')
    for invalid in ('ab' * 32, 'AB' * 31, 'AB' * 33, [171] * 32, 'hash:' + 'AB' * 32 + '#ABCD', '0x' + 'AB' * 32):
        assert not check.is_valid(invalid)


@pytest.mark.parametrize('name', ['NativeByteVectorV1', 'NativeRowByteVectorV1'])
def test_variable_bytes_keep_integer_array_json(document, name):
    check = validator(document, name)
    for valid in ([], [0, 255], [17, 35, 0]):
        check.validate(valid)
    for invalid in ('00FF', 'AP8=', [-1], [256], [True], [1.5], [None]):
        assert not check.is_valid(invalid)


def test_account_value_required_nulls_tuple_identifiers_and_full_stored_label(document, shape_data, subtests):
    check = validator(document, 'NativeAccountValueV1')
    hash_literal = shape_data['network_id']
    label = {'label': 'merchant', 'domain': ['bank'], 'dataspace': 3}
    for value in (
        {'metadata': {}, 'label': None, 'uaid': None, 'opaque_ids': []},
        {'metadata': {'public_shape': {'value': 1}}, 'label': label, 'uaid': [hash_literal], 'opaque_ids': [[hash_literal]]},
    ):
        check.validate(value)
        for field in value:
            with subtests.test(field=field):
                changed = copy.deepcopy(value)
                del changed[field]
                assert not check.is_valid(changed)
    for invalid in (
        {'metadata': {}, 'label': label, 'uaid': hash_literal, 'opaque_ids': []},
        {'metadata': {}, 'label': {'label': 'merchant', 'domain': 'bank', 'dataspace': 3}, 'uaid': None, 'opaque_ids': []},
        {'metadata': {}, 'label': None, 'uaid': None, 'opaque_ids': [hash_literal]},
        {'metadata': {}, 'label': None, 'uaid': None, 'opaque_ids': [], 'id': shape_data['signatory']},
    ):
        assert not check.is_valid(invalid)


@pytest.mark.parametrize('kind', ['AccountAlias', 'GlobalFeeProgram', 'IdentifierPolicy'])
def test_authority_selector_requires_exact_case_and_payload_members(document, shape_data, kind):
    payload = {
        'AccountAlias': {'label': 'merchant', 'domain': None, 'dataspace': 'retail'},
        'GlobalFeeProgram': {
            'program_id': {'sponsor': shape_data['signatory'], 'name': 'fees'},
            'fee_asset': shape_data['asset_definition']['id'],
        },
        'IdentifierPolicy': {'kind': 'email', 'business_rule': 'retail'},
    }[kind]
    selector = {'kind': kind, 'payload': payload}
    check = validator(document, 'NativeAuthorityOriginalsSelectorV1')
    check.validate(selector)
    for malformed in ({'kind': kind.lower(), 'payload': payload}, {'kind': kind, 'value': payload}, {'kind': kind}, {**selector, 'table': 'world.accounts'}):
        assert not check.is_valid(malformed)


def test_native_alias_state_requires_selected_even_when_absent(document):
    value = {'alias': {'label': 'merchant', 'domain': None, 'dataspace': 3}, 'binding_keys': [], 'selected': None}
    check = validator(document, 'NativeAccountAliasStateV1')
    check.validate(value)
    del value['selected']
    assert not check.is_valid(value)


def test_rekey_history_preserves_required_signatory_and_unit_provenance(document, shape_data):
    value = {'label': {'label': 'merchant', 'domain': None, 'dataspace': 3}, 'active_account_id': shape_data['wallet'],
        'previous_account_ids': [shape_data['signatory']], 'active_signatory': None, 'previous_signatories': [],
        'transition_provenance': [{'kind': 'alias_reassignment', 'value': None}]}
    check = validator(document, 'NativeAccountRekeyRecordV1')
    check.validate(value)
    for field in ('active_signatory', 'transition_provenance'):
        changed = copy.deepcopy(value)
        del changed[field]
        assert not check.is_valid(changed)
    for wrong in ({'kind': 'alias_reassignment'}, {'kind': 'AliasReassignment', 'value': None}, {'kind': 'account_id_rekey', 'value': 0}):
        changed = copy.deepcopy(value)
        changed['transition_provenance'] = [wrong]
        assert not check.is_valid(changed)


@pytest.mark.parametrize('schema,path', [
    ('NativeResourceNamesStateV1', 'crates/iroha_torii_shared/src/resource_names_state.rs'),
    ('NativeAuthorityOriginalsV1', 'crates/iroha_torii_shared/src/authority_originals.rs'),
    ('NativeAuthorityOriginalsRequestV1', 'crates/iroha_torii_shared/src/authority_originals.rs'),
    ('NativeAccountAliasStateV1', 'crates/iroha_torii_shared/src/authority_originals.rs'),
    ('NativeAccountAliasOriginalV1', 'crates/iroha_torii_shared/src/authority_originals.rs'),
    ('NativeGlobalFeeProgramStateV1', 'crates/iroha_torii_shared/src/authority_originals.rs'),
    ('NativeIdentifierPolicyStateV1', 'crates/iroha_torii_shared/src/authority_originals.rs'),
])
def test_complete_native_struct_fields_are_required_and_not_query_projections(document, schema, path):
    source = (ROOT / path).read_text()
    body = source.split('pub struct ' + schema + ' {', 1)[1].split('\n}', 1)[0]
    fields = set(re.findall(r'(?m)^    pub ([a-z_][a-z_0-9]*):', body))
    actual = document['components']['schemas'][schema]
    assert set(actual['properties']) == set(actual['required']) == fields
    assert actual['additionalProperties'] is False


@pytest.mark.parametrize('name', RESPONSE_ROOTS)
def test_complete_response_shapes_reject_missing_root_and_unknown_members(document, shape_data, name):
    base = {'attestation': shape_data['attestation'], 'world_snapshot': shape_data['world_snapshot']}
    if name == 'NativeResourceNamesStateV1':
        value = {**base, 'asset_alias_bindings': [{'definition_id': shape_data['asset_definition']['id'], 'binding_record_wire': [0, 255]}],
            'smart_contract_keys': ['public_fixture/path'], 'dataspace_names': [{'storage_key': 'public_fixture/path', 'raw_value': [17, 35]}]}
    else:
        selector = {'kind': 'AccountAlias', 'payload': {'label': 'merchant', 'domain': None, 'dataspace': 'retail'}}
        value = {**base, 'request_sha256': 'AB' * 32, 'selector': selector,
            'originals': {'kind': 'AccountAlias', 'payload': {'alias': {'label': 'merchant', 'domain': None, 'dataspace': 3}, 'binding_keys': [], 'selected': None}}}
    check = validator(document, name)
    check.validate(value)
    for field in value:
        changed = copy.deepcopy(value)
        del changed[field]
        assert not check.is_valid(changed)
    changed = copy.deepcopy(value)
    changed['authority_granted'] = True
    assert not check.is_valid(changed)


@pytest.mark.parametrize('name', ['NativeFeeSponsorProgramRevisionKeyV1', 'NativeFeeSponsorEnrollmentKeyV1', 'NativeFeeSponsorVaultKeyV1', 'NativeFeeSponsorBudgetCounterKeyV1'])
def test_all_four_fee_keys_are_complete_named_objects(document, shape_data, name):
    program = {'sponsor': shape_data['signatory'], 'name': 'fees'}
    value = {'program_id': program}
    if name.endswith('ProgramRevisionKeyV1'):
        value['revision'] = 1
    elif name.endswith('EnrollmentKeyV1'):
        value['beneficiary'] = shape_data['wallet']
    else:
        value['asset_definition_id'] = shape_data['asset_definition']['id']
        if name.endswith('BudgetCounterKeyV1'):
            value['window'] = {'kind': 'block', 'value': {'height': 2}}
    check = validator(document, name)
    check.validate(value)
    for field in value:
        changed = copy.deepcopy(value)
        del changed[field]
        assert not check.is_valid(changed)
    assert not check.is_valid(list(value.values()))
    assert not check.is_valid({**value, 'unknown': 0})


@pytest.mark.parametrize('kind', ['block', 'program_epoch', 'beneficiary_epoch'])
def test_fee_budget_windows_keep_exact_tagged_payload(document, shape_data, kind):
    payload = {'height': 2} if kind == 'block' else {'epoch': 0}
    if kind == 'beneficiary_epoch':
        payload['beneficiary'] = shape_data['wallet']
    value = {'kind': kind, 'value': payload}
    check = validator(document, 'NativeFeeSponsorBudgetWindowV1')
    check.validate(value)
    for invalid in ({'kind': kind}, {'kind': kind.title(), 'value': payload}, {'kind': kind, 'value': None}, {'kind': kind, 'payload': payload}):
        assert not check.is_valid(invalid)


@pytest.mark.parametrize('kind', ['native_instruction', 'multisig', 'contract_call', 'ivm', 'ivm_proved', 'enrolled_multisig_contract_call'])
def test_native_fee_rule_selectors_preserve_all_actual_families(document, shape_data, kind):
    if kind == 'native_instruction':
        payload = {'wire_id': 'public_shape_instruction'}
    elif kind == 'multisig':
        payload = {'operations': [{'operation': 'approve', 'value': None}], 'account_ids': [shape_data['wallet']]}
    elif kind in ('contract_call', 'enrolled_multisig_contract_call'):
        # A shape string, not a native contract-admission or checksum fixture.
        payload = {'contract_address': 'public_contract_shape', 'code_hash': shape_data['network_id'], 'entrypoints': ['main']}
    else:
        payload = {'code_hash': shape_data['network_id']}
    check = validator(document, 'NativeFeeSponsorRuleSelectorV1')
    value = {'kind': kind, 'value': payload}
    check.validate(value)
    for field in payload:
        changed = copy.deepcopy(value)
        del changed['value'][field]
        assert not check.is_valid(changed)
    assert not check.is_valid({'kind': kind.title(), 'value': payload})
    assert not check.is_valid({**value, 'unknown': 0})


def test_native_fee_program_omits_absent_option_fields_instead_of_null(document, shape_data):
    value = {'id': {'sponsor': shape_data['signatory'], 'name': 'fees'}, 'payout_account': shape_data['wallet'],
        'lifecycle': {'state': 'staged', 'value': None}}
    check = validator(document, 'NativeFeeSponsorProgramV1')
    check.validate(value)
    for field in ('active_revision', 'staged_revision', 'scheduled_activation'):
        assert not check.is_valid({**value, field: None})
    check.validate({**value, 'active_revision': 1, 'staged_revision': 2, 'scheduled_activation': {'revision': 2, 'activate_at_height': 3}})
    changed = copy.deepcopy(value)
    del changed['lifecycle']['value']
    assert not check.is_valid(changed)


def test_native_fee_family_retains_complete_rows_and_required_null_program(document, shape_data, subtests):
    program = {'sponsor': shape_data['signatory'], 'name': 'fees'}
    asset = shape_data['asset_definition']['id']
    key = {'program_id': program, 'asset_definition_id': asset}
    value = {'program_id': program, 'fee_asset': asset,
        'asset_keys': [asset + '#' + shape_data['signatory']], 'program_keys': [program],
        'revision_keys': [{'program_id': program, 'revision': 1}],
        'enrollment_keys': [{'program_id': program, 'beneficiary': shape_data['wallet']}],
        'vault_keys': [key], 'budget_counter_keys': [{**key, 'window': {'kind': 'block', 'value': {'height': 2}}}],
        'sponsor_account_value': {'metadata': {}, 'label': None, 'uaid': None, 'opaque_ids': []},
        'fee_asset_definition': shape_data['asset_definition'], 'source_asset_value': '0', 'program': None,
        'revisions': [{'program_id': program, 'revision': 1, 'eligibility': {'mode': 'enrolled_only', 'value': None},
            'rules': [{'id': 'default_fee', 'effect': {'effect': 'allow', 'value': None},
                'selectors': [{'kind': 'ivm', 'value': {'code_hash': shape_data['network_id']}}]}],
            'asset_budgets': [{'asset_definition_id': asset, 'per_transaction': '1', 'per_block': '2', 'per_program_epoch': '3',
                'per_beneficiary_epoch': '1', 'reserve_floor': '0', 'epoch_length_blocks': 1}]}],
        'enrollments': [{'key': {'program_id': program, 'beneficiary': shape_data['wallet']}, 'enrolled_at_height': 2}],
        'vaults': [{'key': key, 'balance': '1'}]}
    check = validator(document, 'NativeGlobalFeeProgramStateV1')
    check.validate(value)
    for field in value:
        with subtests.test(field=field):
            changed = copy.deepcopy(value)
            del changed[field]
            assert not check.is_valid(changed)
    for wrong_quantity in (0, -1, '-1', '01', '1.0'):
        changed = copy.deepcopy(value)
        changed['source_asset_value'] = wrong_quantity
        assert not check.is_valid(changed)
    changed = copy.deepcopy(value)
    changed['revisions'][0]['asset_budgets'][0]['epoch_length_blocks'] = 0
    assert not check.is_valid(changed)
    changed = copy.deepcopy(value)
    changed['vaults'][0]['unknown'] = 0
    assert not check.is_valid(changed)
    changed = copy.deepcopy(value)
    changed['program_keys'] = [program] * 16385
    assert not check.is_valid(changed)


@pytest.mark.parametrize('name', ['NativeNameV1', 'NativeStatePathV1'])
def test_native_text_shapes_refuse_forbidden_characters_and_expose_byte_bounds(document, name):
    check = validator(document, name)
    for valid in ('native_name', 'é', 'public_fixture/path'):
        check.validate(valid)
    for invalid in ('', 'a b', 'a@b', 'a#b', 'a$b', 'a\x00b', 'a؜b', 'a‮b'):
        assert not check.is_valid(invalid)
    expected = 255 if name == 'NativeNameV1' else 16384
    assert document['components']['schemas'][name]['x-iroha-maxUtf8Bytes'] == expected
    assert not check.is_valid('a' * (expected + 1))


def test_every_reachable_struct_is_closed_except_native_metadata(document):
    schemas = document['components']['schemas']
    seen = set()

    def walk(value):
        if isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            if '$ref' in value:
                name = value['$ref'].rsplit('/', 1)[1]
                if name not in seen:
                    seen.add(name)
                    walk(schemas[name])
            if value.get('type') == 'object':
                if 'properties' in value:
                    assert value.get('additionalProperties') is False
                else:
                    assert value.get('additionalProperties') == {'$ref': '#/components/schemas/JsonValue'}
            for key, item in value.items():
                if key != '$ref':
                    # JsonValue is the actual native arbitrary metadata payload.
                    if key == 'additionalProperties' and item == {'$ref': '#/components/schemas/JsonValue'}:
                        continue
                    walk(item)

    for name in RESPONSE_ROOTS:
        walk({'$ref': '#/components/schemas/' + name})
    assert {'SumeragiFinalityAttestation', 'WorldStateSnapshotEntryV1', 'AssetConfidentialPolicy', asset_definition_schema(document)} <= seen


@pytest.mark.parametrize('kind', ['Table', 'Cell'])
def test_world_element_exact_tag_and_explicit_key_absence(document, kind):
    hash_literal = 'hash:' + '11' * 32 + '#ABCD'
    value = {'field_id': 'world.fixture', 'kind': {'kind': kind, 'value': None}, 'key_hash': hash_literal if kind == 'Table' else None, 'value_hash': hash_literal}
    check = validator(document, 'WorldStateSnapshotEntryV1')
    check.validate(value)
    for field in value:
        missing = copy.deepcopy(value)
        del missing[field]
        assert not check.is_valid(missing)
    changed = copy.deepcopy(value)
    changed['key_hash'] = None if kind == 'Table' else hash_literal
    assert not check.is_valid(changed)
    for invalid_kind in ({'kind': kind}, {'kind': kind, 'value': 1}, {'kind': 'Other', 'value': None}, {'kind': kind, 'value': None, 'unknown': 0}):
        changed = copy.deepcopy(value)
        changed['kind'] = invalid_kind
        assert not check.is_valid(changed)


@pytest.mark.parametrize('scale', [None, 0, 1, 28])
def test_numeric_spec_actual_object_shape(document, scale):
    check = validator(document, 'NumericSpec')
    check.validate({'scale': scale})
    for value in ({}, {'scale': scale, 'precision': 512}, {'scale': -1}, {'scale': 29}, {'scale': '2'}, scale):
        assert not check.is_valid(value)


@pytest.mark.parametrize('value', ['Infinitely', 'Once', 'Not', 'Limited(1)', 'Limited(4294967295)'])
def test_mintable_matches_native_string_codec(document, value):
    check = validator(document, 'AssetMintable')
    check.validate(value)
    for malformed in ('Limited(0)', 'Limited(01)', 'Limited(-1)', 'Limited(1.0)', 'Limited(4294967296)', 'Limited(9999999999)', 'Unknown', {'mintable': 'Once'}, 1):
        assert not check.is_valid(malformed)


def test_snapshot_bounds_and_asset_field_set_match_current_sources(document):
    schemas = document['components']['schemas']
    snapshot = (ROOT / 'crates/iroha_data_model/src/sumeragi_finality/world_state.rs').read_text()
    assert 'MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1: usize = 131_072' in snapshot
    assert schemas['WorldStateSnapshotV1']['properties']['entries']['maxItems'] == 131_072
    source = (ROOT / 'crates/iroha_data_model/src/asset/definition.rs').read_text()
    struct = source.split('pub struct AssetDefinition {', 1)[1].split('\n    }', 1)[0]
    fields = set(re.findall(r'pub ([a-z_]+):', struct))
    schema = schemas[asset_definition_schema(document)]
    assert set(schema['properties']) == set(schema['required']) == fields


def test_signed_clock_body_fields_match_current_model_and_uint64_bounds(document):
    source = (ROOT / 'crates/iroha_data_model/src/sumeragi_finality.rs').read_text()
    body = source.split('pub struct SumeragiFinalityAttestationBody {', 1)[1].split('\n}', 1)[0]
    fields = set(re.findall(r'(?m)^    pub ([a-z_]+):', body))
    schema = document['components']['schemas']['SumeragiFinalityAttestationBody']
    assert set(schema['properties']) == set(schema['required']) == fields
    assert schema['additionalProperties'] is False
    assert 'self.observed_at_unix_ms != 0' in source
    clock = schema['properties']['observed_at_unix_ms']
    assert clock['type'] == 'integer' and clock['format'] == 'uint64'
    assert clock['minimum'] == 1 and clock['maximum'] == (1 << 64) - 1
    check = Draft202012Validator(clock)
    for value in (1, 1_000_000, (1 << 64) - 1):
        check.validate(value)
    for value in (0, -1, 1 << 64, '1000000', True, None):
        assert not check.is_valid(value), value


@pytest.fixture(scope='module')
def native_shapes(document, shape_data):
    # The shape file copies native output byte-for-byte; see its README.
    validator(document, 'SumeragiFinalityAttestation').validate(shape_data['attestation'])
    validator(document, 'WorldStateSnapshotV1').validate(shape_data['world_snapshot'])
    validator(document, asset_definition_schema(document)).validate(shape_data['asset_definition'])
    return shape_data


def test_native_shapes_are_data_only_attestation_output(native_shapes):
    body = native_shapes['attestation']['body']
    assert body['status']['protocol_version'] == 1
    assert body['status']['applied_height'] == 2
    assert body['observed_at_unix_ms'] == 1_000_000


def test_native_shapes_reject_unknown_nested_members_and_missing_fields(document, native_shapes):
    schema_names = {
        'attestation': 'SumeragiFinalityAttestation',
        'world_snapshot': 'WorldStateSnapshotV1',
        'asset_definition': asset_definition_schema(document),
    }
    attestation = validator(document, schema_names['attestation'])
    for challenge in ([7] * 32, '0' * 64, 'ab' * 32, 'AB' * 31, 'AB' * 33):
        changed = copy.deepcopy(native_shapes['attestation'])
        changed['body']['challenge'] = challenge
        assert not attestation.is_valid(changed)
    for root, path in NESTED_SHAPES:
        check = validator(document, schema_names[root])
        original = native_shapes[root]
        changed = copy.deepcopy(original)
        descend(changed, path)['trusted_root'] = 'caller-selected'
        assert not check.is_valid(changed), (root, path)
        for field in descend(original, path):
            missing = copy.deepcopy(original)
            del descend(missing, path)[field]
            assert not check.is_valid(missing), (root, path, field)


def test_exact_enrollment_read_has_signed_scoped_absence_contract(document, shape_data):
    operation = document['paths']['/v1/fee-sponsor-enrollments/by-id']['post']
    assert operation['security'] == SECURITY
    assert operation['x-iroha-tool-effect'] == 'read'
    assert operation['x-iroha-route-auth'] == {
        'admission': 'authenticated_account',
        'authentication': 'canonical_account_signature',
        'schemaVersion': 1,
        'stableRouteId': 'fee_sponsor_enrollment.by_id',
    }
    assert set(operation['responses']) == {'200', '400', '401', '403', '404'}
    assert 'expired' in operation['responses']['401']['description']
    assert 'sponsor' in operation['responses']['403']['description']
    assert 'program' in operation['responses']['404']['description']
    assert operation['requestBody']['content']['application/json']['schema']['$ref'] == '#/components/schemas/FeeSponsorEnrollmentByIdRequest'
    assert operation['responses']['200']['content']['application/json']['schema']['$ref'] == '#/components/schemas/FeeSponsorEnrollmentByIdResponse'
    key = {'program_id': {'sponsor': shape_data['signatory'], 'name': 'fees'}, 'beneficiary': shape_data['wallet']}
    check = validator(document, 'FeeSponsorEnrollmentByIdResponse')
    for row in [None, {'key': key, 'enrolled_at_height': 7}]:
        check.validate({'key': key, 'enrollment': row})
    for malformed in [{}, {'key': key}, {'enrollment': None}, {'key': key, 'enrollment': None, 'extra': True}, {'key': key, 'enrollment': {}}]:
        assert not check.is_valid(malformed)
    request = validator(document, 'FeeSponsorEnrollmentByIdRequest')
    good = {'program_id': shape_data['signatory'] + '/fees', 'beneficiary': shape_data['wallet']}
    request.validate(good)
    for malformed in [{}, {'program_id': good['program_id']}, {**good, 'extra': True}]:
        assert not request.is_valid(malformed)


@pytest.fixture
def identifier_originals(shape_data):
    """Synthetic original shapes only; these confer no ledger or policy authority."""
    program_id = {'name': 'email-retail'}
    public_key = shape_data['attestation']['body']['node_id']
    return {
        'policy': {
            'id': {'kind': 'email', 'business_rule': 'retail'},
            'owner': shape_data['signatory'],
            'normalization': {'normalization': 'email_address', 'value': None},
            'program_id': program_id,
            'active': False,
        },
        'program': {
            'program_id': program_id,
            'owner': shape_data['signatory'],
            'backend': 'hkdf-sha3-512-prf-v1',
            'verification_mode': {'mode': 'signed', 'value': None},
            'commitment': {
                'backend': 'hkdf-sha3-512-prf-v1',
                'policy_hash': shape_data['network_id'],
                'public_parameters': [0, 255],
            },
            'resolver_public_key': public_key,
            'output_opening_public_key': public_key,
            'active': False,
        },
    }


def test_identifier_policy_family_is_complete_in_the_shared_authority_carrier(document, shape_data, identifier_originals):
    selector = {'kind': 'IdentifierPolicy', 'payload': identifier_originals['policy']['id']}
    originals = {'kind': 'IdentifierPolicy', 'payload': identifier_originals}
    value = {
        'attestation': shape_data['attestation'],
        'world_snapshot': shape_data['world_snapshot'],
        'request_sha256': 'AB' * 32,
        'selector': selector,
        'originals': originals,
    }
    validator(document, 'NativeAuthorityOriginalsV1').validate(value)
    check = validator(document, 'NativeAuthorityOriginalsFamilyV1')
    check.validate(originals)
    for malformed in (
        {'kind': 'identifier_policy', 'payload': identifier_originals},
        {'kind': 'IdentifierPolicy', 'value': identifier_originals},
        {'kind': 'IdentifierPolicy'},
        {**originals, 'authority_granted': True},
        {'kind': 'IdentifierPolicy', 'payload': None},
    ):
        assert not check.is_valid(malformed)


@pytest.mark.parametrize('path', [
    (), ('policy',), ('program',), ('policy', 'id'), ('policy', 'normalization'),
    ('policy', 'program_id'), ('program', 'program_id'),
    ('program', 'verification_mode'), ('program', 'commitment'),
])
def test_identifier_originals_require_complete_rows_and_reject_unknown_fields(document, identifier_originals, path):
    check = validator(document, 'NativeIdentifierPolicyStateV1')
    check.validate(identifier_originals)
    original = descend(identifier_originals, path)
    for field in original:
        missing = copy.deepcopy(identifier_originals)
        del descend(missing, path)[field]
        assert not check.is_valid(missing), (path, field)
    changed = copy.deepcopy(identifier_originals)
    descend(changed, path)['trusted_root'] = 'caller-selected'
    assert not check.is_valid(changed)


@pytest.mark.parametrize('path,replacement', [
    (('policy', 'id'), 'email#retail'),
    (('policy', 'program_id'), 'email-retail'),
    (('program', 'program_id'), 'email-retail'),
    (('policy', 'normalization'), 'email_address'),
    (('program', 'verification_mode'), 'signed'),
    (('program', 'backend'), 'hash-prf-v1'),
    (('program', 'commitment', 'public_parameters'), '00FF'),
    (('program', 'commitment', 'public_parameters'), [256]),
    (('program', 'commitment', 'public_parameters'), [-1]),
    (('program', 'commitment', 'public_parameters'), [True]),
    (('program', 'commitment', 'policy_hash'), 'AB' * 32),
    (('policy', 'active'), 'false'),
])
def test_identifier_originals_do_not_accept_summary_or_coerced_scalar_shapes(document, identifier_originals, path, replacement):
    changed = copy.deepcopy(identifier_originals)
    descend(changed, path[:-1])[path[-1]] = replacement
    assert not validator(document, 'NativeIdentifierPolicyStateV1').is_valid(changed)


def test_identifier_selector_uses_the_exact_typed_policy_key(document):
    check = validator(document, 'NativeAuthorityOriginalsSelectorV1')
    for payload in (
        'email#retail', {'kind': 'email'}, {'business_rule': 'retail'},
        {'kind': 'email', 'business_rule': 'retail', 'owner': 'caller-selected'},
        {'kind': 'email#retail', 'business_rule': 'retail'},
        {'kind': 'email', 'business_rule': ''},
    ):
        assert not check.is_valid({'kind': 'IdentifierPolicy', 'payload': payload})


@pytest.mark.parametrize('schema,tag,variants', [
    ('IdentifierNormalization', 'normalization', ['exact', 'lowercase_trimmed', 'phone_e164', 'email_address', 'account_number']),
    ('RamLfeVerificationMode', 'mode', ['signed', 'proof']),
])
def test_identifier_native_unit_enums_require_explicit_null_content(document, schema, tag, variants):
    check = validator(document, schema)
    for variant in variants:
        check.validate({tag: variant, 'value': None})
        for malformed in (
            variant, {tag: variant}, {tag: variant, 'value': 0},
            {tag: variant.upper(), 'value': None}, {tag: variant, 'value': None, 'extra': True},
        ):
            assert not check.is_valid(malformed)


@pytest.mark.parametrize('backend', ['hkdf-sha3-512-prf-v1', 'bfv-affine-v1', 'bfv-programmed-v1'])
def test_original_backend_tags_are_native_data_without_execution_authority(document, identifier_originals, backend):
    value = copy.deepcopy(identifier_originals)
    value['program']['backend'] = backend
    value['program']['commitment']['backend'] = backend
    validator(document, 'NativeIdentifierPolicyStateV1').validate(value)
    assert not validator(document, 'RamLfeBackend').is_valid(backend.upper())
    assert not validator(document, 'RamLfeBackend').is_valid({'backend': backend})


def test_identifier_original_optional_fields_follow_native_omission(document, identifier_originals, shape_data):
    check = validator(document, 'NativeIdentifierPolicyStateV1')
    check.validate(identifier_originals)
    value = copy.deepcopy(identifier_originals)
    value['policy']['phone_retail_attestor_public_key'] = shape_data['attestation']['body']['node_id']
    value['policy']['note'] = 'Synthetic note'
    value['program']['note'] = ''
    value['program']['commitment']['public_parameters'] = []
    check.validate(value)
    for row, field in [('policy', 'phone_retail_attestor_public_key'), ('policy', 'note'), ('program', 'note')]:
        changed = copy.deepcopy(value)
        changed[row][field] = None
        assert not check.is_valid(changed)


@pytest.mark.parametrize('schema,path,optional', [
    ('IdentifierPolicyId', 'crates/iroha_data_model/src/identifier.rs', set()),
    ('IdentifierPolicy', 'crates/iroha_data_model/src/identifier.rs', {'phone_retail_attestor_public_key', 'note'}),
    ('RamLfeProgramId', 'crates/iroha_data_model/src/ram_lfe.rs', set()),
    ('RamLfeProgramPolicy', 'crates/iroha_data_model/src/ram_lfe.rs', {'note'}),
    ('PolicyCommitment', 'crates/iroha_crypto/src/ram_lfe.rs', set()),
])
def test_identifier_original_schemas_keep_actual_fields_and_native_omissions(document, schema, path, optional):
    source = (ROOT / path).read_text()
    body = source.split('pub struct ' + schema + ' {', 1)[1].split('\n}', 1)[0]
    fields = set(re.findall(r'(?m)^    pub ([a-z_][a-z_0-9]*):', body))
    omitted = set(re.findall(r'#\[norito\(skip_serializing_if = "Option::is_none"\)\]\s*#\[norito\(default\)\]\s*pub ([a-z_][a-z_0-9]*):', body))
    assert omitted == optional
    actual = document['components']['schemas'][schema]
    Draft202012Validator.check_schema(actual)
    assert set(actual['properties']) == fields
    assert set(actual['required']) == fields - optional
    assert actual['additionalProperties'] is False
