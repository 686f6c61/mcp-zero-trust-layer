from __future__ import annotations

import pytest

from mcp_zero_trust_layer.config.models import InputPolicy
from mcp_zero_trust_layer.validators.basic import validate_email, validate_sql_read_only
from mcp_zero_trust_layer.validators.input_policy import validate_input_policy


@pytest.mark.parametrize("recipient", [
    "attacker@evil.test, trusted@company.test", "attacker@evil.test; trusted@company.test",
    "trusted@company.test\r\nBcc: attacker@evil.test", "@company.test", "a@@company.test",
    "Person <trusted@company.test>", "a@", "a@company..test", "a@company.test (comment)", 7,
])
def test_email_rejects_ambiguous_or_malformed_recipient(recipient):
    assert not validate_email({"to": [recipient]}, {"allowed_domains": ["company.test"]}).passed


def test_email_accepts_explicit_mailbox_list_and_normalizes_domain_options():
    assert validate_email(
        {"to": ["one@company.test", "two@COMPANY.TEST"]},
        {"allowed_domains": ["COMPANY.TEST"]},
    ).passed
    assert not validate_email(
        {"to": "one@company.test"}, {"blocked_domains": ["COMPANY.TEST"]}
    ).passed


@pytest.mark.parametrize("customer", [[{"secret": "leak"}], [], "leak", 5, None])
def test_nested_allowed_fields_reject_non_object_ancestors(customer):
    assert not validate_input_policy(
        {"customer": customer}, InputPolicy(allowed_fields=["customer.name"])
    ).passed


def test_nested_allowed_fields_keep_explicit_subtree_semantics():
    assert validate_input_policy(
        {"customer": {"name": "Ana"}}, InputPolicy(allowed_fields=["customer.name"])
    ).passed
    assert validate_input_policy(
        {"customer": [{"name": "Ana"}]}, InputPolicy(allowed_fields=["customer"])
    ).passed


@pytest.mark.parametrize("query", [
    "SELECT '--'; DELETE FROM demo;", "SELECT '/*'; DELETE FROM demo; -- */",
    "SELECT 'a''--'; DELETE FROM demo;", "SELECT nextval('invoice_seq')",
    "SELECT setval('invoice_seq', 10)", "SELECT pg_advisory_lock(1)",
    "SELECT set_config('role', 'admin', false)", "SELECT arbitrary_udf()",
    'SELECT "nextval"(\'seq\')', "SELECT pg_catalog.nextval('seq')",
    "SELECT malicious . count(*) FROM demo",
    "SELECT NEXT VALUE FOR invoice_seq", "SELECT * FROM t FOR SHARE",
    "SELECT 'unterminated", 'SELECT "unterminated', "SELECT 1 /* unterminated",
    "SELECT 1 /* outer /* nested */ tail */", "SELECT 1 /*! DELETE FROM demo */",
    "SELECT 1 /*+ optimizer */", r"SELECT 'back\slash'", "SELECT $$dollar$$",
    "SELECT `identifier` FROM t", "SELECT [identifier] FROM t", "SELECT 1\x00",
])
def test_sql_blocks_lexical_bypasses_side_effects_and_unsupported_syntax(query):
    assert not validate_sql_read_only({"query": query}, {}).passed, query


@pytest.mark.parametrize("query", [
    "SELECT '--';", "SELECT '/* literal */';", "SELECT 'DELETE FROM demo';",
    "SELECT 'a''--b; DELETE'; -- trailing comment", 'SELECT "column" FROM "table"',
    "/* ordinary comment */ SELECT count(*) FROM demo; -- end",
    "SELECT sum(value), lower(name) FROM demo GROUP BY name",
    "SELECT (1 + 2)", "WITH a AS (SELECT 1) SELECT * FROM a",
    "SELECT 1 -- trailing line comment without newline",
    "SELECT 1 -- line\nFROM demo", "SELECT '/*! literal */'",
    "SELECT 'quote''quote'", 'SELECT "quoted""identifier" FROM demo',
])
def test_sql_retains_ordinary_select_literals_comments_and_safe_functions(query):
    assert validate_sql_read_only({"query": query}, {}).passed, query
