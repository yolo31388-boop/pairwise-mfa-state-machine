import pytest
import security.mfa_state_machine as mod

CASES = [
    ("half_login", (1, 2)),
    ("restricted_token", (1, 2)),
    ("verify_timestamp", (1, 2)),
    ("server_state", (1, 2)),
    ("audit", (1, 2)),
    ("bypass_guard", (1, 2)),
    ("session_flag", (1, 2)),
    ("step_up", (1, 2)),
    ("validation", (1, 2)),
    ("error_map", (1, 2)),
    ("rate_limit", (1, 2)),
    ("lockout", (1, 2)),
    ("recovery", (1, 2)),
    ("logging", (1, 2)),
    ("test_matrix", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
