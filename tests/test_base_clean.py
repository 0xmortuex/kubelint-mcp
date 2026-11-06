"""The base manifest used by every mutation test must itself be clean, or the mutation tests prove nothing."""

import pytest

from conftest import build_base


@pytest.mark.parametrize("prefix", ["K8S1", "K8S2", "K8S3"])
def test_base_has_no_findings(lint_text, prefix):
    found = lint_text(build_base(), prefix)
    assert found == [], [(f.rule, f.line, f.message) for f in found]
