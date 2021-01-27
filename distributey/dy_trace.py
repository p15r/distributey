"""Provides functionality to trace execution flow of distributey."""

import os
import inspect
from inspect import ArgInfo
from typing import Optional, Any
from types import FrameType
import logging
import re

logger = logging.getLogger(__name__)


# add all keys from log
# add tracing
# add unittest
def __camouflage(func_args: ArgInfo):
    # ArgInfo contains file descriptors and can therefore not be
    # copy.deepcopy()-ed. (deepcopy pickles and unpickles object.
    # during this process a file descriptor state will get lost,
    # thus an exception is thrown that the object cannot be deepcopy()ed)
    # as a hack, access a string representation,
    # camouflage sensitive values and give back
    # the string representation of the ArgInfo object

    str_func_args = func_args.__repr__()

    # still original objects that cannot be deepcopy()-ed
    # d_func_args = func_args._asdict()
    # d_func_args = func_args.__getnewargs__()

    print(f'++++++++++++++++++++++ ORIG: {str_func_args}')

    str_func_args = re.sub(r'\s+', ' ', str_func_args)   # remove all tabs, newlines and spaces

    # replace: 'locals' -> 'header_args' -> 'jwt'
    camouflaged_func_args = re.sub(
        r'(.*)(locals)(.*)(header_args)(.*)(jwt\': \')([0-9a-zA-Z]*)([.\-_0-9a-zA-Z\s]*)(\'.*)',
        r'\1\2\3\4\5\6******\9',
        str_func_args)

    print(f'############### REPLACED: {camouflaged_func_args}')

    return camouflaged_func_args


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
        logger.error('Failed to inspect frame: "%s".', current_frame)
        return ('error', 'error', 'error', 'error')

    str_func_args = __camouflage(func_args)

    return func_name, str_func_args, file_name, line_no


def trace_enter(current_frame: Optional[FrameType]) -> None:
    """Traces execution flow when entering a function/method."""

    func_name, cp_func_args, file_name, line_no = __trace(current_frame)

    logger.info('(%s:%s) Entering "%s" args: %s',
                file_name, line_no, func_name, cp_func_args)


def trace_exit(current_frame: Optional[FrameType], ret: Any) -> None:
    """Traces execution flow when exiting a function/method."""

    func_name, cp_func_args, file_name, line_no = __trace(current_frame)

    logger.info('(%s:%s) Exiting "%s" ret: %s',
                file_name, line_no, func_name, ret)
