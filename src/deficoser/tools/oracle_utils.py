from __future__ import annotations

def sink_function_name(violation: dict | None) -> str | None:
    if not violation:
        return None
    sink = violation.get('sink') or ''
    if not isinstance(sink, str):
        return None
    name = sink.rsplit('.', 1)[-1].split('(', 1)[0].strip()
    return name or None

def has_authorization_violation(foundry_result: dict | None, violation: dict | None=None) -> bool:
    if not foundry_result:
        return False
    evidence = foundry_result.get('evidence') or []
    auth_evidence = [item for item in evidence if item.get('category') == 'authorization']
    if not auth_evidence:
        return False
    if not foundry_result.get('test_passed'):
        return False
    sink_name = sink_function_name(violation)
    if sink_name is None:
        return True
    return any((sink_name.lower() in (item.get('detail') or '').lower() for item in auth_evidence))
