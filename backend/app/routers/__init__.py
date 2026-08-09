from app.logging_utils import get_logger
from app.routers import (
	agentic,
	agents,
	audit,
	auth,
	benchmark_scan,
	browser_security,
	compliance,
	cost,
	discovery,
	gateway,
	governance,
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
	"browser_security",
	"compliance",
	"cost",
	"discovery",
	"modules",
	"gateway",
	"governance",
	"observability",
	"playground",
	"providers",
	"route_drafts",
]
