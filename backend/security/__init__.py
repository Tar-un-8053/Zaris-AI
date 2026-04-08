def arm_security_mode(*args, **kwargs):
    from backend.security.manager import arm_security_mode as _arm_security_mode

    return _arm_security_mode(*args, **kwargs)


def disarm_security_mode(*args, **kwargs):
    from backend.security.manager import disarm_security_mode as _disarm_security_mode

    return _disarm_security_mode(*args, **kwargs)


def get_security_status_message(*args, **kwargs):
    from backend.security.manager import get_security_status_message as _get_security_status_message

    return _get_security_status_message(*args, **kwargs)


def get_startup_security_message(*args, **kwargs):
    from backend.security.manager import get_startup_security_message as _get_startup_security_message

    return _get_startup_security_message(*args, **kwargs)


def handle_security_command(*args, **kwargs):
    from backend.security.manager import handle_security_command as _handle_security_command

    return _handle_security_command(*args, **kwargs)


def verify_owner_identity(*args, **kwargs):
    from backend.security.manager import verify_owner_identity as _verify_owner_identity

    return _verify_owner_identity(*args, **kwargs)


def is_security_enabled(*args, **kwargs):
    from backend.security.manager import is_security_enabled as _is_security_enabled

    return _is_security_enabled(*args, **kwargs)


def start_cyber_security_services(*args, **kwargs):
    from backend.security.manager import start_cyber_security_services as _start_cyber_security_services

    return _start_cyber_security_services(*args, **kwargs)


def should_block_regular_command(*args, **kwargs):
    from backend.security.manager import should_block_regular_command as _should_block_regular_command

    return _should_block_regular_command(*args, **kwargs)


__all__ = [
    "arm_security_mode",
    "disarm_security_mode",
    "get_security_status_message",
    "get_startup_security_message",
    "handle_security_command",
    "is_security_enabled",
    "start_cyber_security_services",
    "should_block_regular_command",
    "verify_owner_identity",
]
