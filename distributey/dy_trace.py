"""Provides functionality to trace execution flow of distributey."""

import copy
import os
import inspect
from inspect import ArgInfo
from typing import Optional, Any, Dict, List
from types import FrameType
import logging

import glom

logger = logging.getLogger(__name__)
CAMOUFLAGE_SIGN = '******'


def __get_dict_keypaths(
        a_dict: dict, current_path: str = '', depth: int = 0
) -> list:
    """Generates list of keypaths of a dict."""
    if depth > 15:
        logger.critical(
            'Camouflage aborted, dict exceeded depth "%i".' % depth
        )
        return []
    depth += 1

    keypaths: List[str] = list()
    for key, value in a_dict.items():
        if isinstance(value, dict):
            new_keypaths = __get_dict_keypaths(
                value,
                current_path=current_path + f'{key}.',
                depth=depth)
            keypaths.extend(new_keypaths)
        else:
            keypaths.append(current_path + f'{key}')

    return keypaths


def __camouflage(func_args: ArgInfo, effective_args: List) -> Dict:
    """
    Takes dict of a function's arguments and censors sensitive
    arguments by replacing their values with '******'.
    """
    arguments_and_values: Dict[Any, Any] = dict()

    for arg in effective_args:
        if arg not in func_args.locals:
            # The value of an argument might not exist anymore if the variable
            # has been explicitely deleted within the function (eg. "del var").
            arguments_and_values[arg] = '<MISSING>'
            continue
        if arg.startswith('priv_'):
            arguments_and_values[arg] = CAMOUFLAGE_SIGN
            continue

        if isinstance(func_args.locals[arg], dict):
            # arg is a dict, let's check for keys marked as private as well

            # copy all data (also sensitive), camouflage it afterwords
            # this way, arguments_and_values[arg] has the correct
            # data structure. Otherwise the data structure must be
            # reproduced, which is unnecessary complex.
            # Note: deepcopy() does not work on file descriptors
            arguments_and_values[arg] = copy.deepcopy(func_args.locals[arg])

            keypaths = __get_dict_keypaths(func_args.locals[arg])

            # e.g. "path.to.priv_key.subkey"
            for keypath in keypaths:
                # e.g. "priv_key.subkey"
                if (pos_start := keypath.find('priv_')) != -1:
                    # e.g. "priv_key"
                    pos_end = keypath[pos_start:].find('.')
                    # e.g. "path.to.priv_key"
                    if pos_end == -1:
                        # if keypath is only "priv_key", then end_pos is end
                        # of string
                        pos_end = len(keypath)

                    priv_keypath = keypath[:pos_start+pos_end]

                    glom.assign(
                        arguments_and_values[arg],
                        priv_keypath,
                        CAMOUFLAGE_SIGN
                    )
            continue

        arguments_and_values[arg] = func_args.locals[arg]

    return arguments_and_values


def __extract_arguments(func_args: ArgInfo) -> Dict:
    """
    Extracts a function's arguments and returns dict with
    argument name as key and argument value as value.
    """
    effective_args = list()

    if func_args.args:
        effective_args.extend(func_args.args)

    if func_args.varargs:
        if isinstance(func_args.varargs, list):
            effective_args.extend(func_args.varargs)
        else:
            effective_args.append(func_args.varargs)

    if func_args.keywords:
        if isinstance(func_args.keywords, list):
            effective_args.extend(func_args.keywords)
        else:
            effective_args.append(func_args.keywords)

    res = __camouflage(func_args, effective_args)

    return res


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

    filtered_func_args = __extract_arguments(func_args)

    return func_name, filtered_func_args, file_name, line_no


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
