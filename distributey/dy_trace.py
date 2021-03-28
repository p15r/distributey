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
NESTED_DICT_DEPTH_MAX = 15


def __get_dict_keypaths(
        a_dict: dict, current_path: str = '', depth: int = 0
) -> list:
    """Generates list of keypaths of a dict, max. dict nested depth is 15."""

    if depth > NESTED_DICT_DEPTH_MAX:
        logger.critical(
            'Aborting, nested dict depth ("%i") exceeded.', depth - 1
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
            keypaths.append(current_path + key)

    return keypaths


def __camouflage_nested_dict(args_and_values: dict, keypaths: List[str]):
    # example keypath: "path.to.priv_key.subkey"
    for keypath in keypaths:
        # "priv_key.subkey"
        if (pos_start := keypath.find('priv_')) != -1:
            # "priv_key"
            pos_end = keypath[pos_start:].find('.')

            if pos_end == -1:
                # if keypath is only "priv_key", then end_pos is end
                # of string
                pos_end = len(keypath)

            # "path.to.priv_key"
            priv_keypath = keypath[:pos_start+pos_end]

            # camouflage sensitive value of argument
            try:
                glom.assign(
                    args_and_values,
                    priv_keypath,
                    CAMOUFLAGE_SIGN
                )
            except Exception as exc:
                logger.critical(
                    'Failed to camouflage sensitive argument '
                    'for path "%s".'
                    'Exception: "%s"', keypath, exc
                )

                # Keep sensitive value in log instead of aborting
                # logging.
                continue


def __camouflage(func_args: ArgInfo, effective_args: List) -> Dict:
    """
    Processes arguments of a function and censors sensitive argument values by
    replacing them with CAMOUFLAGE_SIGN.
    Sensitive arguments are recognized by their prefix "priv_" in the variable
    name (e.g. "priv_arg1").

    Note: all function arguments are deepcopy()-ed to avoid interference with
    arguments that haven't been processed yet by the interpreter.
    deepcopy() doesn't work if an argument is an open file descriptor.
    """

    arguments_and_values: Dict[Any, Any] = dict()

    for arg in effective_args:
        if arg not in func_args.locals:
            # The value of an argument might not exist anymore if the variable
            # has been explicitely deleted within the function (eg. "del var").
            arguments_and_values[arg] = '<MISSING>'
            continue
        if arg.startswith('priv_'):
            # found sensitive argument, camouflage its value
            arguments_and_values[arg] = CAMOUFLAGE_SIGN
            continue

        if isinstance(func_args.locals[arg], dict):
            # arg is a dict, let's check for keys marked as private as well

            # Copy all arguments (also sensitive values) and camouflage them
            # afterwards. If original data is not copied, its data
            # structure, that might contains many nested dicts, must be
            # reproduced, which is unnecessary complex.
            arguments_and_values[arg] = copy.deepcopy(func_args.locals[arg])

            keypaths = __get_dict_keypaths(func_args.locals[arg])

            __camouflage_nested_dict(arguments_and_values[arg], keypaths)

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
