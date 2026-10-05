"""服务层可观察错误。"""


class ServiceError(RuntimeError):
    code = "service_error"
    status = 400


class NotFound(ServiceError):
    code = "not_found"
    status = 404


class Conflict(ServiceError):
    code = "conflict"
    status = 409


class Forbidden(ServiceError):
    code = "forbidden"
    status = 403


class InvalidState(ServiceError):
    code = "invalid_state"
    status = 409


class ValidationFailed(ServiceError):
    code = "validation_failed"
    status = 422


class DisclosureDenied(Forbidden):
    """披露包当前不可读取；访问事实仍会被记录。"""

    code = "disclosure_denied"
    status = 403

    def __init__(self, reason: str) -> None:
        super().__init__(f"披露包已不可读: {reason}")
        self.reason = reason
