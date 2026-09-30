import asyncio
from sentinel_core.modules.persistence.database import engine
from sentinel_core.models import Base
import sentinel_core.models.core # Ensure models are loaded

async def init_db():
    print("Initializing SQLite database and creating tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database initialized successfully.")

if __name__ == "__main__":
    asyncio.run(init_db())
