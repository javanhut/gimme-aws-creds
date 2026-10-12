"""Tests for bugs fixed in the code improvement plan (Phase 1)."""

import json
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from gimme_aws_creds import errors
from gimme_aws_creds.common import (
    RoleSet,
    parse_saml_form,
    parse_saml_role_attributes,
    user_agent,
)
from gimme_aws_creds.main import GimmeAWSCreds


class TestParseRoleArnNullSafety(unittest.TestCase):
    """BUG-5: _parse_role_arn should raise GimmeAWSCredsError on bad ARN."""

    def test_valid_arn(self):
        result = GimmeAWSCreds._parse_role_arn("arn:aws:iam::123456789012:role/MyRole")
        self.assertEqual(result["account"], "123456789012")
        self.assertEqual(result["role"], "MyRole")

    def test_invalid_arn_raises(self):
        with self.assertRaises(errors.GimmeAWSCredsError) as ctx:
            GimmeAWSCreds._parse_role_arn("not-an-arn")
        self.assertIn("Unrecognized AWS IAM role ARN", ctx.exception.message)

    def test_empty_arn_raises(self):
        with self.assertRaises(errors.GimmeAWSCredsError):
            GimmeAWSCreds._parse_role_arn("")


class TestNamingDataForRole(unittest.TestCase):
    """BUG: _naming_data_for_role now delegates to _parse_role_arn with fallback."""

    def test_aws_arn(self):
        creds = GimmeAWSCreds()
        result = creds._naming_data_for_role("arn:aws:iam::123456789012:role/Admin")
        self.assertEqual(result["account"], "123456789012")
        self.assertEqual(result["role"], "Admin")

    def test_alicloud_arn(self):
        creds = GimmeAWSCreds()
        result = creds._naming_data_for_role("acs:ram::111122223333:role/MyRole")
        self.assertEqual(result["account"], "111122223333")
        self.assertEqual(result["role"], "MyRole")

    def test_invalid_arn_raises(self):
        creds = GimmeAWSCreds()
        with self.assertRaises(errors.GimmeAWSCredsError):
            creds._naming_data_for_role("completely-invalid")


class TestWriteResultActionAlicloud(unittest.TestCase):
    """BUG-2: write_result_action should handle AliCloud credentials."""

    def setUp(self):
        self.creds = GimmeAWSCreds()
        self.creds.ui = MagicMock()

    def test_json_format(self):
        data = {
            "role": {"arn": "acs:ram::123:role/R"},
            "credentials": {
                "credentials_type": "alibaba_cloud",
                "access_key_id": "ak",
                "access_key_secret": "sk",
                "security_token": "st",
            },
        }
        self.creds.write_result_action("json", data)
        self.creds.ui.result.assert_called_once()
        output = self.creds.ui.result.call_args[0][0]
        parsed = json.loads(output)
        self.assertEqual(parsed["credentials"]["access_key_id"], "ak")

    def test_export_format_aws(self):
        data = {
            "role": {"arn": "arn:aws:iam::123:role/R"},
            "credentials": {
                "credentials_type": "aws",
                "aws_access_key_id": "ak",
                "aws_secret_access_key": "sk",
                "aws_session_token": "st",
                "aws_security_token": "st",
            },
        }
        self.creds.write_result_action("export", data)
        calls = [c[0][0] for c in self.creds.ui.result.call_args_list]
        self.assertTrue(any("AWS_ACCESS_KEY_ID" in c for c in calls))

    def test_export_format_alicloud(self):
        data = {
            "role": {"arn": "acs:ram::123:role/R"},
            "credentials": {
                "credentials_type": "alibaba_cloud",
                "access_key_id": "ak",
                "access_key_secret": "sk",
                "security_token": "st",
            },
        }
        self.creds.write_result_action("export", data)
        calls = [c[0][0] for c in self.creds.ui.result.call_args_list]
        self.assertTrue(any("ALIBABA_CLOUD_ACCESS_KEY_ID" in c for c in calls))
        self.assertFalse(any("AWS_ACCESS_KEY_ID" in c for c in calls))

    def test_windows_format_alicloud(self):
        data = {
            "role": {"arn": "acs:ram::123:role/R"},
            "credentials": {
                "credentials_type": "alibaba_cloud",
                "access_key_id": "ak",
                "access_key_secret": "sk",
                "security_token": "st",
            },
        }
        self.creds.write_result_action("windows", data)
        calls = [c[0][0] for c in self.creds.ui.result.call_args_list]
        self.assertTrue(any("$env:ALIBABA_CLOUD_ACCESS_KEY_ID" in c for c in calls))


class TestParseSamlForm(unittest.TestCase):
    """Test the shared parse_saml_form utility."""

    def test_valid_form(self):
        html = """<html><body><form action="https://example.com/saml">
        <input name="SAMLResponse" value="abc123"/>
        <input name="RelayState" value="rs"/>
        </form></body></html>"""
        saml, relay, action = parse_saml_form(html)
        self.assertEqual(saml, "abc123")
        self.assertEqual(relay, "rs")
        self.assertEqual(action, "https://example.com/saml")

    def test_no_saml(self):
        html = "<html><body>No form here</body></html>"
        saml, relay, action = parse_saml_form(html)
        self.assertIsNone(saml)
        self.assertIsNone(relay)
        self.assertIsNone(action)


class TestParseSamlRoleAttributes(unittest.TestCase):
    """Test the shared parse_saml_role_attributes utility."""

    def test_extract_roles(self):
        import base64

        saml_xml = """<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
          <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AttributeStatement>
              <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
                <saml2:AttributeValue>arn:aws:iam::123456789012:saml-provider/Okta,arn:aws:iam::123456789012:role/Admin</saml2:AttributeValue>
              </saml2:Attribute>
            </saml2:AttributeStatement>
          </saml2:Assertion>
        </saml2p:Response>"""
        assertion_b64 = base64.b64encode(saml_xml.encode()).decode()
        results = list(
            parse_saml_role_attributes(
                assertion_b64, "https://aws.amazon.com/SAML/Attributes/Role"
            )
        )
        self.assertEqual(len(results), 1)
        self.assertIn("saml-provider", results[0])

    def test_no_matching_attribute(self):
        import base64

        saml_xml = """<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
          <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AttributeStatement>
              <saml2:Attribute Name="other">
                <saml2:AttributeValue>value</saml2:AttributeValue>
              </saml2:Attribute>
            </saml2:AttributeStatement>
          </saml2:Assertion>
        </saml2p:Response>"""
        assertion_b64 = base64.b64encode(saml_xml.encode()).decode()
        results = list(
            parse_saml_role_attributes(
                assertion_b64, "https://aws.amazon.com/SAML/Attributes/Role"
            )
        )
        self.assertEqual(len(results), 0)


class TestUserAgent(unittest.TestCase):
    """Test the shared user_agent utility."""

    def test_format(self):
        ua = user_agent()
        self.assertTrue(ua.startswith("gimme-aws-creds"))
        parts = ua.split(";")
        self.assertEqual(len(parts), 3)


class TestAcsPartitionParsing(unittest.TestCase):
    """Test the data-driven ACS URL partition parsing."""

    def test_aws_commercial(self):
        p, r = GimmeAWSCreds._get_partition_and_region_from_saml_acs(
            "https://us-west-2.signin.aws.amazon.com/saml"
        )
        self.assertEqual(p, "aws")
        self.assertEqual(r, "us-west-2")

    def test_aws_china(self):
        p, r = GimmeAWSCreds._get_partition_and_region_from_saml_acs(
            "https://cn-northwest-1.signin.amazonaws.cn/saml"
        )
        self.assertEqual(p, "aws-cn")
        self.assertEqual(r, "cn-northwest-1")

    def test_aws_govcloud(self):
        p, r = GimmeAWSCreds._get_partition_and_region_from_saml_acs(
            "https://us-gov-west-1.signin.amazonaws-us-gov.com/saml"
        )
        self.assertEqual(p, "aws-us-gov")
        self.assertEqual(r, "us-gov-west-1")

    def test_unknown_raises(self):
        with self.assertRaises(errors.GimmeAWSCredsError):
            GimmeAWSCreds._get_partition_and_region_from_saml_acs(
                "https://unknown.example.com/saml"
            )

    def test_no_region_prefix_aws(self):
        p, r = GimmeAWSCreds._get_partition_and_region_from_saml_acs(
            "https://signin.aws.amazon.com/saml"
        )
        self.assertEqual(p, "aws")
        self.assertEqual(r, "us-east-1")

    def test_no_region_prefix_china(self):
        p, r = GimmeAWSCreds._get_partition_and_region_from_saml_acs(
            "https://signin.amazonaws.cn/saml"
        )
        self.assertEqual(p, "aws-cn")
        self.assertEqual(r, "cn-north-1")

    def test_no_region_prefix_govcloud(self):
        p, r = GimmeAWSCreds._get_partition_and_region_from_saml_acs(
            "https://signin.amazonaws-us-gov.com/saml"
        )
        self.assertEqual(p, "aws-us-gov")
        self.assertEqual(r, "us-gov-east-1")


class TestSelectionErrorMessages(unittest.TestCase):
    """4B: Error messages should include expected range."""

    @patch("builtins.input", return_value="5")
    def test_choose_app_error_includes_range(self, mock):
        creds = GimmeAWSCreds()
        aws_info = [{"name": "a"}, {"name": "b"}]
        with self.assertRaises(errors.GimmeAWSCredsError) as ctx:
            creds._choose_app(aws_info)
        self.assertIn("0", str(ctx.exception))
        self.assertIn("1", str(ctx.exception))


class TestOktaSdkTupleResults(unittest.TestCase):
    """The Okta SDK returns (result, response, error) tuples instead of raising."""

    @staticmethod
    def _client(get_user, list_app_links):
        from unittest.mock import AsyncMock

        client = MagicMock()
        client.get_user = AsyncMock(return_value=get_user)
        client.list_app_links = AsyncMock(return_value=list_app_links)
        return client

    def test_app_links_are_unpacked(self):
        user = MagicMock(id="00u1")
        aws = MagicMock(
            app_name="amazon_aws", id="a1", label="AWS", link_url="l", logo_url="g"
        )
        other = MagicMock(app_name="slack")
        client = self._client((user, None, None), ([aws, other], None, None))
        with patch("gimme_aws_creds.main.OktaManagementClient", return_value=client):
            result = GimmeAWSCreds._get_aws_account_info("https://x.okta.com", "k", "u")
        self.assertEqual([app["name"] for app in result], ["AWS"])
        client.list_app_links.assert_awaited_once_with("00u1")

    def test_user_not_found(self):
        err = MagicMock(status=404, error_summary="Not found: Resource not found")
        client = self._client((None, None, err), None)
        with patch("gimme_aws_creds.main.OktaManagementClient", return_value=client):
            with self.assertRaises(errors.GimmeAWSCredsError) as ctx:
                GimmeAWSCreds._get_aws_account_info("https://x.okta.com", "k", "u")
        self.assertIn("u was not found", ctx.exception.message)

    def test_api_error_summary(self):
        err = MagicMock(status=401, error_summary="Invalid token provided")
        client = self._client((None, None, err), None)
        with patch("gimme_aws_creds.main.OktaManagementClient", return_value=client):
            with self.assertRaises(errors.GimmeAWSCredsError) as ctx:
                GimmeAWSCreds._get_aws_account_info("https://x.okta.com", "k", "u")
        self.assertIn("Invalid token provided", ctx.exception.message)


class TestStoreJsonCredsWithoutType(unittest.TestCase):
    """JSON from older versions has no credentials_type and must still be stored as AWS."""

    def test_missing_credentials_type_defaults_to_aws(self):
        creds = GimmeAWSCreds()
        creds.ui = MagicMock()
        creds._write_aws_credentials = MagicMock()
        creds.write_credentials_from_data(
            {
                "profile": {"name": "p"},
                "credentials": {
                    "aws_access_key_id": "a",
                    "aws_secret_access_key": "s",
                    "aws_session_token": "t",
                    "expiration": "e",
                },
            }
        )
        creds._write_aws_credentials.assert_called_once_with(
            "p", "a", "s", "t", "e", credentials_file=None
        )


class TestRolePatterns(unittest.TestCase):
    ROLES = [RoleSet("idp", "arn:aws:iam::123456789012:role/a(b", "", "")]

    def test_literal_role_is_not_compiled_as_regex(self):
        creds = GimmeAWSCreds()
        self.assertEqual(
            creds._get_selected_roles(self.ROLES[0].role, self.ROLES),
            {self.ROLES[0].role},
        )

    def test_invalid_pattern_is_reported(self):
        creds = GimmeAWSCreds()
        with self.assertRaises(errors.GimmeAWSCredsError):
            creds._get_selected_roles("/a(b/", self.ROLES)


class TestFactorChoiceRange(unittest.TestCase):
    """len(factors) is one past the last valid index."""

    def test_upper_bound_is_exclusive(self):
        from gimme_aws_creds.okta_classic import OktaClassicClient

        ui = MagicMock()
        ui.input.side_effect = ["2", "1"]
        client = OktaClassicClient(ui, "https://example.okta.com")
        self.assertEqual(client._get_user_int_factor_choice(2), 1)
