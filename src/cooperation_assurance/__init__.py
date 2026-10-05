"""跨境合作项目证据评估、准入与分级披露服务。"""

from . import disclosure
from .contracts import Observation, Protocol, ValidationError
from .analysis import ALGORITHM_VERSION, analyze, bootstrap_mean_interval
from .numeric import NumericSummary, WilsonInterval
from .service import AssuranceService

__all__ = [
    "NumericSummary",
    "Observation",
    "Protocol",
    "ValidationError",
    "WilsonInterval",
    "ALGORITHM_VERSION",
    "AssuranceService",
    "analyze",
    "bootstrap_mean_interval",
    "disclosure",
]

__version__ = "0.1.0"
