from app.logging_utils import get_logger
from app.routers import (
	agentic,
	agents,
	audit,
	auth,
	benchmark_scan,
	compliance,
	cost,
	discovery,
	gateway,
	modules,
	observability,
	playground,
	providers,
	route_drafts,
)

logger = get_logger(__name__)

__all__ = [
	"agents",
	"agentic",
	"audit",
	"auth",
	"benchmark_scan",
	"compliance",
	"cost",
	"discovery",
	"modules",
	"gateway",
	"observability",
	"playground",
	"providers",
	"route_drafts",
]
