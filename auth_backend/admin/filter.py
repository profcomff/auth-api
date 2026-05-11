import anyio
from sqladmin.forms import ModelConverter
from sqladmin.helpers import is_async_session_maker
from sqlalchemy import select


class FilteredModelConverter(ModelConverter):
    """
    A custom ModelConverter that filters out deleted objects from select options in form with create/update.
    """

    async def _prepare_select_options(self, prop, session_maker):
        target_model = prop.mapper.class_
        stmt = select(target_model)
        if hasattr(target_model, "is_deleted"):
            stmt = stmt.where(target_model.is_deleted == False)
        if is_async_session_maker(session_maker):
            async with session_maker() as session:
                objects = await session.execute(stmt)
                return [(str(self._get_identifier_value(obj)), str(obj)) for obj in objects.scalars().unique().all()]
        else:
            with session_maker() as session:
                objects = await anyio.to_thread.run_sync(session.execute, stmt)
                return [(str(self._get_identifier_value(obj)), str(obj)) for obj in objects.scalars().unique().all()]
