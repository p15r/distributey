"""Provides functionality to trace execution flow of distributey."""

import os
import inspect
from inspect import ArgInfo
from typing import Optional, Any, Dict
from types import FrameType
import logging

logger = logging.getLogger(__name__)


def __extract_arguments(func_args: ArgInfo) -> Dict:
    all_args = list()

    args = func_args.args
    if args:
        all_args.extend(args)

    varargs = func_args.varargs
    if varargs:
        if isinstance(varargs, list):
            all_args.extend(varargs)
        else:
            all_args.append(varargs)

    keywords = func_args.keywords
    if keywords:
        if isinstance(keywords, list):
            all_args.extend(keywords)
        else:
            all_args.append(keywords)

    arg_value = dict()
    for arg in all_args:
        if arg not in func_args.locals:
            # The value of an argument might not exist if the variable has
            # been explicitely deleted.
            arg_value[arg] = '<MISSING>'
            continue
        if arg.startswith('priv_'):
            # camouflage
            arg_value[arg] = '******'
            continue

        if isinstance(func_args.locals[arg], dict):
            # arg is a dict, let's check for keys marked as private
            keys = func_args.locals[arg].keys()
            arg_value[arg] = dict()
            for key in keys:
                if key.startswith('priv_'):
                    arg_value[arg][key] = '******'
                else:
                    arg_value[arg][key] = func_args.locals[arg][key]
            continue

        arg_value[arg] = func_args.locals[arg]

    return arg_value


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
        # in case of "exotic" python runtime env
        logger.error('Failed to inspect frame: "%s".', current_frame)
        return ('error', 'error', 'error', 'error')

    func_args = __extract_arguments(func_args)

    return func_name, func_args, file_name, line_no


def trace_enter(current_frame: Optional[FrameType]) -> None:
    """Traces execution flow when entering a function/method."""

    func_name, func_args, file_name, line_no = __trace(current_frame)

    logger.info('(%s:%s) Entering "%s" args: %s',
                file_name, line_no, func_name, func_args)


def trace_exit(current_frame: Optional[FrameType], ret: Any) -> None:
    """Traces execution flow when exiting a function/method."""

    func_name, func_args, file_name, line_no = __trace(current_frame)

    logger.info('(%s:%s) Exiting "%s" ret: %s',
                file_name, line_no, func_name, ret)
