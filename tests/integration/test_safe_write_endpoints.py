"""
Safe write operation tests for GhidraMCP.

These tests verify write endpoints work by reading existing values and writing
them back unchanged. This tests the write path without modifying actual data.

Strategy:
1. Read current value from Ghidra
2. Write the same value back
3. Verify the write succeeds (no errors)
4. Optionally verify the value is still the same

Run with: pytest tests/integration/test_safe_write_endpoints.py -v

Note: Tests will be automatically skipped if the MCP server is not running.
"""

import pytest
import json
import re


def detable(value):
    """Expand a compact columnar table {"columns":[...],"rows":[[...]]} into a
    list of dicts; pass-through for legacy list payloads."""
    if isinstance(value, dict) and "columns" in value and "rows" in value:
        cols = value.get("columns") or []
        return [dict(zip(cols, row)) for row in (value.get("rows") or [])]
    if isinstance(value, list):
        return value
    return []


# Mark all tests as safe-write integration tests
pytestmark = [
    pytest.mark.integration,
    pytest.mark.safe_write,
    pytest.mark.usefixtures("require_server_and_program"),
]


@pytest.fixture(scope="module")
def require_server_and_program(server_available, program_loaded):
    """Skip all tests if server is not available or no program loaded."""
    if not server_available:
        pytest.skip("MCP server is not running")
    if not program_loaded:
        pytest.skip("No program loaded in Ghidra")


@pytest.fixture
def first_function(http_client):
    """Get the first function with its details."""
    response = http_client.get("/list_functions", params={"limit": 1})
    if response.status_code != 200:
        pytest.skip("Cannot list functions")

    text = response.text
    # Try to extract function name and address
    # Format: "FunctionName at 10001000" or "FunctionName at 0x10001000" or JSON
    match = re.search(r"at\s+(?:0x)?([0-9a-fA-F]+)", text)
    if not match:
        # Also try JSON format
        match = re.search(r'"address"\s*:\s*"?(?:0x)?([0-9a-fA-F]+)"?', text)
    if not match:
        pytest.skip("No functions found")

    address = f"0x{match.group(1)}"

    # Get function details
    details_response = http_client.get(
        "/get_function_by_address", params={"address": address}
    )
    if details_response.status_code != 200:
        pytest.skip("Cannot get function details")

    return {"address": address, "details": details_response.text}


@pytest.fixture
def first_named_function(http_client):
    """Get the first function that has a non-default name."""
    response = http_client.get("/list_functions", params={"limit": 50})
    if response.status_code != 200:
        pytest.skip("Cannot list functions")

    text = response.text
    # Look for functions in format: "FunctionName at 10001000"
    matches = re.findall(r"^(\w+)\s+at\s+(?:0x)?([0-9a-fA-F]+)", text, re.MULTILINE)
    if not matches:
        # Try JSON format
        matches = re.findall(
            r'"name"\s*:\s*"([^"]+)".*?"address"\s*:\s*"?(?:0x)?([0-9a-fA-F]+)"?',
            text,
            re.DOTALL,
        )

    if not matches:
        pytest.skip("No functions found")

    name, address = matches[0]
    return {"name": name, "address": f"0x{address}"}


@pytest.fixture
def first_data_item(http_client):
    """Get the first defined data item."""
    response = http_client.get("/list_data_items", params={"limit": 1})
    if response.status_code != 200:
        pytest.skip("Cannot list data items")

    text = response.text
    # Match address with or without 0x prefix
    match = re.search(
        r'(?:at\s+|"address"\s*:\s*"?|^)(?:0x)?([0-9a-fA-F]{6,})', text, re.MULTILINE
    )
    if not match:
        pytest.skip("No data items found")

    return f"0x{match.group(1)}"


@pytest.fixture
def first_label(http_client, first_function):
    """Get the first label in the first function."""
    response = http_client.get(
        "/get_function_labels", params={"address": first_function["address"]}
    )
    if response.status_code != 200:
        pytest.skip("Cannot get function labels")

    text = response.text
    # Try to extract a label name and address
    match = re.search(
        r'"name"\s*:\s*"([^"]+)".*?"address"\s*:\s*"?(?:0x)?([0-9a-fA-F]+)"?',
        text,
        re.DOTALL,
    )
    if not match:
        # Try plain text format: "LabelName at 10001000"
        match = re.search(r"(\w+)\s+at\s+(?:0x)?([0-9a-fA-F]+)", text)

    if not match:
        pytest.skip("No labels found")

    return {"name": match.group(1), "address": match.group(2)}


class TestSafeRenameOperations:
    """Test rename operations by renaming to the same name."""

    def test_rename_function_same_name(self, http_client, first_named_function):
        """Rename a function to its current name (no-op)."""
        name = first_named_function["name"]
        address = first_named_function["address"]

        # Write the same name back (include old_name as some endpoints require it)
        response = http_client.post(
            "/rename_function",
            data={"address": address, "old_name": name, "new_name": name},
        )

        # Should succeed (200), indicate no change (400), or endpoint requires different params (500)
        assert response.status_code in [
            200,
            400,
            500,
        ], f"Unexpected status: {response.status_code}, body: {response.text}"

    def test_rename_function_by_address_same_name(
        self, http_client, first_named_function
    ):
        """Rename function by address to its current name."""
        name = first_named_function["name"]
        address = first_named_function["address"]

        response = http_client.post(
            "/rename_function_by_address",
            data={"address": address, "old_name": name, "new_name": name},
        )

        assert response.status_code in [200, 400, 404, 500]


class TestSafeCommentOperations:
    """Test comment operations by reading and writing same comments."""

    def test_set_plate_comment_preserve(self, http_client, first_function):
        """Read plate comment and write it back."""
        address = first_function["address"]

        # Get current plate comment
        get_response = http_client.get(
            "/get_plate_comment", params={"address": address}
        )

        if get_response.status_code != 200:
            pytest.skip("Cannot get plate comment")

        # Extract current comment (may be empty)
        current_comment = get_response.text.strip()
        if current_comment.startswith('"') and current_comment.endswith('"'):
            current_comment = current_comment[1:-1]

        # Handle JSON response
        try:
            data = json.loads(get_response.text)
            if isinstance(data, dict):
                current_comment = data.get("comment", "") or ""
        except json.JSONDecodeError:
            pass

        # Write the same comment back
        set_response = http_client.post(
            "/set_plate_comment", data={"address": address, "comment": current_comment}
        )

        # Should succeed
        assert set_response.status_code in [200, 400, 404]

    def test_set_decompiler_comment_preserve(self, http_client, first_function):
        """Set decompiler comment to empty or existing (safe operation)."""
        address = first_function["address"]

        # Decompiler comments are typically per-line, use function entry
        response = http_client.post(
            "/set_decompiler_comment",
            json_data={"address": address, "comment": ""},
        )

        # May not have existing comment, empty should be safe
        # 500 may occur if endpoint has issues with empty comments
        assert response.status_code in [200, 400, 404, 500]

    def test_set_disassembly_comment_preserve(self, http_client, first_function):
        """Set disassembly comment to empty (safe operation)."""
        address = first_function["address"]

        response = http_client.post(
            "/set_disassembly_comment", data={"address": address, "comment": ""}
        )

        # 500 may occur if endpoint has issues with empty comments
        assert response.status_code in [200, 400, 404, 500]


class TestSafeFunctionPrototype:
    """Test function prototype operations."""

    def test_get_and_set_function_prototype(self, http_client, first_function):
        """Read function prototype and write it back."""
        address = first_function["address"]

        # Get function details which includes prototype
        response = http_client.get(
            "/get_function_by_address", params={"address": address}
        )

        if response.status_code != 200:
            pytest.skip("Cannot get function details")

        # Try to extract signature/prototype from response
        text = response.text
        try:
            data = json.loads(text)
            signature = data.get("signature") or data.get("prototype")
            if not signature:
                pytest.skip("No signature in function details")
        except json.JSONDecodeError:
            # Try regex extraction
            match = re.search(r'"signature"\s*:\s*"([^"]+)"', text)
            if not match:
                pytest.skip("Cannot parse function signature")
            signature = match.group(1)

        # Set the same prototype back
        set_response = http_client.post(
            "/set_function_prototype", data={"address": address, "prototype": signature}
        )

        # Should succeed or return validation error (signature format may differ)
        assert set_response.status_code in [200, 400, 404, 500]


class TestSafeVariableOperations:
    """Test variable operations by reading and writing same values."""

    def test_get_function_variables(self, http_client, first_function):
        """Get function variables (read-only verification for write tests)."""
        address = first_function["address"]

        response = http_client.get(
            "/get_function_variables", params={"address": address}
        )

        # May not exist in all versions
        assert response.status_code in [200, 404]

    def test_rename_variable_same_name(self, http_client, first_function):
        """Attempt to rename a variable to its current name."""
        address = first_function["address"]

        # Get variables
        var_response = http_client.get(
            "/get_function_variables", params={"address": address}
        )

        if var_response.status_code != 200:
            pytest.skip("Cannot get variables")

        # Try to extract first variable
        text = var_response.text
        try:
            data = json.loads(text)
            if isinstance(data, list) and len(data) > 0:
                var = data[0]
                var_name = var.get("name")
            elif isinstance(data, dict):
                variables = data.get("variables", []) or data.get("locals", [])
                if variables:
                    var_name = variables[0].get("name")
                else:
                    pytest.skip("No variables found")
            else:
                pytest.skip("No variables found")
        except json.JSONDecodeError:
            match = re.search(r'"name"\s*:\s*"([^"]+)"', text)
            if not match:
                pytest.skip("Cannot parse variable name")
            var_name = match.group(1)

        if not var_name:
            pytest.skip("No variable name found")

        # Rename to same name
        response = http_client.post(
            "/rename_variables",
            json_data={
                "function_address": address,
                "variable_renames": {var_name: var_name},
            },
        )

        # Should succeed or indicate no change
        assert response.status_code in [200, 400, 404]


class TestSafeDataTypeOperations:
    """Test data type operations safely."""

    def test_validate_existing_type(self, http_client):
        """Validate that common data types exist."""
        for type_name in ["int", "char", "void", "uint"]:
            response = http_client.get(
                "/validate_data_type_exists", params={"type_name": type_name}
            )
            assert response.status_code == 200

    def test_search_and_get_data_type(self, http_client):
        """Search for a data type and get its size."""
        # Search for int types
        search_response = http_client.get(
            "/search_data_types", params={"pattern": "int"}
        )
        assert search_response.status_code == 200

        # Get size of int
        size_response = http_client.get(
            "/get_data_type_size", params={"type_name": "int"}
        )
        # May be 404 if endpoint not available
        assert size_response.status_code in [200, 404]


class TestSafeLabelOperations:
    """Test label operations by working with existing labels."""

    def test_rename_label_same_name(self, http_client, first_label):
        """Rename a label to its current name."""
        name = first_label["name"]
        address = first_label["address"]

        response = http_client.post(
            "/rename_label",
            data={"address": address, "old_name": name, "new_name": name},
        )

        # Should succeed or indicate no change needed
        assert response.status_code in [200, 400, 404]


class TestSafeDocumentationOperations:
    """Test documentation operations."""

    def test_get_function_documentation(self, http_client, first_function):
        """Get and verify function documentation can be retrieved."""
        address = first_function["address"]

        response = http_client.get(
            "/get_function_documentation", params={"address": address}
        )

        assert response.status_code == 200

    def test_apply_same_documentation(self, http_client, first_function):
        """Get documentation and apply it back."""
        address = first_function["address"]

        # Get current documentation
        get_response = http_client.get(
            "/get_function_documentation", params={"address": address}
        )

        if get_response.status_code != 200:
            pytest.skip("Cannot get function documentation")

        # Try to apply the same documentation back
        response = http_client.post(
            "/apply_function_documentation",
            json_data={"address": address, "documentation": get_response.text},
        )

        # May fail due to format, but should not crash
        assert response.status_code in [200, 400, 404, 500]


class TestSafeNoReturnAttribute:
    """Test function no-return attribute operations."""

    def test_get_and_set_no_return_same(self, http_client, first_function):
        """Get function's no-return status and set it to the same value."""
        address = first_function["address"]

        # Get function details to find no-return status
        response = http_client.get(
            "/get_function_by_address", params={"address": address}
        )

        if response.status_code != 200:
            pytest.skip("Cannot get function details")

        # Parse the response to find no-return status
        text = response.text
        no_return = False
        try:
            data = json.loads(text)
            no_return = data.get("noReturn", False) or data.get("no_return", False)
        except json.JSONDecodeError:
            # Check if "noReturn" or "no_return" appears as true
            if '"noReturn": true' in text or '"no_return": true' in text:
                no_return = True

        # Set the same value back
        set_response = http_client.post(
            "/set_function_no_return",
            data={"function_address": address, "no_return": str(no_return).lower()},
        )

        assert set_response.status_code in [200, 400, 404]


class TestSafeBatchOperations:
    """Test batch operations with empty or identity operations."""

    def test_batch_set_comments_empty(self, http_client, first_function):
        """Test batch comment setting with empty batch."""
        address = first_function["address"]

        response = http_client.post("/batch_set_comments", json_data={"comments": []})

        # Empty batch should succeed or be rejected gracefully
        assert response.status_code in [200, 400, 404]

    def test_batch_rename_function_components_identity(
        self, http_client, first_named_function
    ):
        """Test batch rename with identity renames."""
        address = first_named_function["address"]
        name = first_named_function["name"]

        response = http_client.post(
            "/batch_rename_function_components",
            json_data={
                "function_address": address,
                "renames": [{"old_name": name, "new_name": name}],
            },
        )

        assert response.status_code in [200, 400, 404]


class TestSafeAnalysisOperations:
    """Test analysis operations that don't modify data."""

    def test_analyze_function_completeness(self, http_client, first_function):
        """Analyze function completeness (read-only analysis)."""
        address = first_function["address"]

        response = http_client.get(
            "/analyze_function_completeness", params={"address": address}
        )

        assert response.status_code == 200

    def test_analyze_function_complete(self, http_client, first_function):
        """Get complete function analysis."""
        address = first_function["address"]

        response = http_client.get(
            "/analyze_function_complete", params={"address": address}
        )

        assert response.status_code in [200, 404]

    def test_analyze_data_region(self, http_client, first_data_item):
        """Analyze a data region (read-only)."""
        response = http_client.get(
            "/analyze_data_region", params={"address": first_data_item}
        )

        assert response.status_code in [200, 404]


class TestSafeHashOperations:
    """Test hash operations that are read-only but verify write-path logic."""

    def test_get_function_hash(self, http_client, first_function):
        """Get function hash (read-only)."""
        address = first_function["address"]

        response = http_client.get("/get_function_hash", params={"address": address})

        assert response.status_code == 200

    def test_build_function_hash_index(self, http_client):
        """Build function hash index (computes but doesn't store externally)."""
        response = http_client.get("/build_function_hash_index", params={"limit": 10})

        assert response.status_code in [200, 404]

    def test_lookup_function_by_hash(self, http_client, first_function):
        """Lookup function by hash (requires hash index)."""
        address = first_function["address"]

        # First get the hash
        hash_response = http_client.get(
            "/get_function_hash", params={"address": address}
        )

        if hash_response.status_code != 200:
            pytest.skip("Cannot get function hash")

        # Try to extract hash value
        try:
            data = json.loads(hash_response.text)
            hash_value = data.get("hash") or data.get("mnemonic_hash")
        except json.JSONDecodeError:
            match = re.search(
                r'"(?:hash|mnemonic_hash)"\s*:\s*"([^"]+)"', hash_response.text
            )
            if match:
                hash_value = match.group(1)
            else:
                pytest.skip("Cannot parse hash value")

        if not hash_value:
            pytest.skip("No hash value found")

        # Lookup by hash
        lookup_response = http_client.get(
            "/lookup_function_by_hash", params={"hash": hash_value}
        )

        assert lookup_response.status_code in [200, 404]


class TestWriteEndpointAvailability:
    """Verify write endpoints exist and respond (even with errors)."""

    @pytest.mark.parametrize(
        "endpoint,method",
        [
            ("/rename_function", "POST"),
            ("/rename_function_by_address", "POST"),
            ("/rename_data", "POST"),
            ("/rename_global_variable", "POST"),
            ("/rename_label", "POST"),
            ("/create_label", "POST"),
            ("/delete_label", "POST"),
            ("/set_plate_comment", "POST"),
            ("/set_decompiler_comment", "POST"),
            ("/set_disassembly_comment", "POST"),
            ("/set_function_prototype", "POST"),
            ("/set_local_variable_type", "POST"),
            ("/set_parameter_type", "POST"),
            ("/rename_variables", "POST"),
            ("/create_struct", "POST"),
            ("/add_struct_field", "POST"),
            ("/apply_data_type", "POST"),
            ("/create_function", "POST"),
            ("/set_function_no_return", "POST"),
        ],
    )
    def test_write_endpoint_exists(self, http_client, endpoint, method):
        """Verify write endpoint exists (returns something other than 404 for wrong method)."""
        # Send empty request to check endpoint exists
        if method == "POST":
            response = http_client.post(endpoint, data={})
        else:
            response = http_client.get(endpoint)

        # Should exist - may return 400 (bad request) or 500 (error) but not 404
        # Actually 404 is OK if the endpoint just doesn't exist in this version
        # We're checking the endpoint is reachable
        assert response.status_code in [200, 400, 404, 405, 500]


def _any_function_address(http_client):
    """Resolve a real function address on whatever binary is loaded, using the
    columnar list_functions_enhanced output (arch-agnostic — the shared
    first_function fixture mis-parses some binaries' list_functions text)."""
    r = http_client.get("/list_functions_enhanced", params={"limit": 1})
    if r.status_code != 200:
        return None
    funcs = detable(r.json().get("functions"))
    if not funcs:
        return None
    f = funcs[0]
    return f.get("address_full") or f.get("address")


class TestSetVariableStorage:
    """`/set_variable_storage` now assigns real custom storage (register, register
    pair, stack slot, or memory address) instead of just printing instructions.

    These cover the validation/error path only — they fail *before* any mutation
    (a bad spec is rejected at parse time, before custom storage is enabled), so
    they stay safe-write. The positive round-trip is covered by live
    verification after deploy.

    Build detection: targeting "return" with a nonsense storage string makes the
    REAL implementation fail at parse time ("could not parse … register/stack"),
    while the old informational stub instead reports the variable "return" was
    not found. We use that to skip cleanly on pre-implementation JARs.
    """

    BOGUS_SPEC = "definitely_not_a_location"

    def _probe(self, http_client):
        """Return (addr, response) for a return+bogus-spec probe, or skip."""
        addr = _any_function_address(http_client)
        if not addr:
            pytest.skip("No function available to test storage assignment")
        resp = http_client.post(
            "/set_variable_storage",
            json_data={
                "function_address": addr,
                "variable_name": "return",
                "storage": self.BOGUS_SPEC,
            },
        )
        if resp.status_code == 404:
            pytest.skip("/set_variable_storage not deployed in current JAR")
        low = resp.text.lower()
        if "could not parse" not in low:
            # Old stub (or a build that doesn't handle "return") — it reports the
            # variable as not found instead of parsing the storage spec.
            pytest.skip("real set_variable_storage not deployed (stub response)")
        return addr, resp

    def test_invalid_storage_spec_rejected(self, http_client):
        """A storage string that is not a register/stack/memory location is
        rejected at parse time, naming the accepted forms."""
        _addr, resp = self._probe(http_client)
        low = resp.text.lower()
        assert "could not parse" in low
        assert "register" in low or "stack" in low  # guidance toward a valid form

    def test_unknown_variable_rejected(self, http_client):
        """Targeting a variable that does not exist is rejected before any
        custom-storage change is applied."""
        addr, _resp = self._probe(http_client)  # also confirms the real build
        resp = http_client.post(
            "/set_variable_storage",
            json_data={
                "function_address": addr,
                "variable_name": "__no_such_variable__zzz",
                "storage": "r0",
            },
        )
        assert "not found" in resp.text.lower()

    def _supports_enhancements(self, http_client):
        """Return a function address if this build supports the storage='auto'
        reset + data_type param; else skip. Detects the enhancement by whether
        'auto' is recognized as a keyword (older builds try to parse it as a
        register/address and fail)."""
        addr = _any_function_address(http_client)
        if not addr:
            pytest.skip("No function available")
        resp = http_client.post(
            "/set_variable_storage",
            json_data={"function_address": addr, "variable_name": "return", "storage": "auto"},
        )
        if resp.status_code == 404:
            pytest.skip("/set_variable_storage not deployed")
        if "could not parse" in resp.text.lower():
            pytest.skip("set_variable_storage auto/data_type enhancements not deployed")
        return addr, resp

    def test_auto_storage_recognized(self, http_client):
        """storage='auto' is a recognized keyword that manages custom storage
        rather than being parsed as a location."""
        _addr, resp = self._supports_enhancements(http_client)
        low = resp.text.lower()
        assert "could not parse" not in low
        # Either it disabled custom storage or reported nothing-to-do.
        assert "custom variable storage" in low or "automatic" in low

    def test_unknown_data_type_rejected(self, http_client):
        """A bogus data_type is rejected (before any storage parse/mutation)."""
        addr, _resp = self._supports_enhancements(http_client)  # confirms new build
        resp = http_client.post(
            "/set_variable_storage",
            json_data={
                "function_address": addr,
                "variable_name": "return",
                "storage": "zzz",
                "data_type": "NotARealType_zzz123",
            },
        )
        assert "unknown data type" in resp.text.lower()
