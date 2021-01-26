import os
import inspect
from typing import Optional, Any
from types import FrameType
import logging

logger = logging.getLogger(__name__)


def __trace(current_frame: Optional[FrameType]) -> tuple:
    if isinstance(current_frame, FrameType):
        func_name = current_frame.f_code.co_name
        # getargvalues is deprecated, use inspect.signature() instead
        func_args = inspect.getargvalues(current_frame)
        file_path = current_frame.f_code.co_filename
        file_name = os.path.basename(file_path)
        line_no = current_frame.f_code.co_firstlineno
    else:
        # inspect.currentframe() might return None,
        # in case of "exotic" python runtime
        logger.error(f'Failed to inspect frame: "{current_frame}".')
        return ('error', 'error', 'error', 'error')

    return func_name, func_args, file_name, line_no


def trace_enter(current_frame: Optional[FrameType]) -> None:
    func_name, func_args, file_name, line_no = __trace(current_frame)

    logger.info(
        f'({file_name}:{line_no}) Entering "{func_name}" args: {func_args}')


def trace_exit(current_frame: Optional[FrameType], ret: Any) -> None:
    func_name, func_args, file_name, line_no = __trace(current_frame)

    logger.info(f'({file_name}:{line_no}) Exiting "{func_name}" ret: {ret}')
