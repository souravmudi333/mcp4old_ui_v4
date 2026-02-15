# mcpgateway/cache/session_registry_singleton.py
from mcpgateway.cache import SessionRegistry
from mcpgateway.config import settings

session_registry = SessionRegistry(
  backend=settings.cache_type,
  redis_url=settings.redis_url if settings.cache_type == "redis" else None,
  database_url=settings.database_url if settings.cache_type == "database" else None,
  session_ttl=settings.session_ttl,
  message_ttl=settings.message_ttl,
)
