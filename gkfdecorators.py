# -*- coding: utf-8 -*-
import typing
from   typing import *

"""
These decorators are designed to handle hard errors in operation
and provide a stack unwind and dump.

Usage:

from gkfdecorators import show_exceptions_and_frames as trap

@trap
def a_function_that_crashes():
    pass

When the decorator is invoked, it will create a file named 

$PWD/YYYY-MM-DD/pidNNNNN

Where:
    $PWD -- is the current working directory of the process (not
        the human user of who started the process).
    YYYY-MM-DD -- the ordinary Gregorian date based on the system
        clock.
    pidNNNNN -- where NNNNN is the process identification number of
        the process that created the dump.

"""

# System imports
import contextlib
import datetime
import inspect
import os
import sys
import types

# Credits
__author__     = 'George Flanagin'
__copyright__  = 'Copyright 2019, George Flanagin'
__credits__    = 'Based on Github Gist 1148066 by diosmosis'
__version__    = '1.1'
__maintainer__ = 'George Flanagin'
__email__      = 'me+python@georgeflanagin.com'
__status__     = 'Production'
__license__    = 'MIT'


###
# Part 1: a couple of helper functions.
###

def make_dir_or_die(dirname:str, mode:int=0o700) -> None:
    """
    Do our best to make the given directory (and any required
    directories upstream). If we cannot, then die trying.

    dirname -- name you would like to use.
    mode    -- permissions on the directory.

    returns -- None
    """

    try:
        os.makedirs(dirname, mode)

    except FileExistsError as e:
        # It's already there.
        pass

    except PermissionError as e:
        # This is bad.
        tombstone(f"Permissions error creating/using {dirname}")
        sys.exit(os.EX_NOPERM)

    except NotADirectoryError as e:
        tombstone("{dirname} exists, but it is not a directory")
        sys.exit(os.EX_CANTCREAT)

    except Exception as e:
        tombstone(str(e))
        sys.exit(os.EX_IOERR)

    if (os.stat(dirname).st_mode & 0o777) >= mode:
        return
    else:
        tombstone("{dirname} created. Permissions less than requested.")


def now_as_string(s:str = "T") -> str:
    """
    Return full timestamp, fixed width for printing, parsing, and readability:

    2007-02-07 @ 23:11:45
    """
    return datetime.datetime.now().isoformat()[:21].replace("T",s)


def tombstone(o:Any) -> str:
    """
    Write the representation of o to stderr, and also return it as
    a courtesy.
    """
    rep = f"{o}\n"
    sys.stderr.write(rep)
    return rep


###
# Part 2: The main event.
###

def show_exceptions_and_frames(func:object) -> None:
    """
    Produce a full dump of the symbol table.
    """

    def wrapper(*args, **kwds):
        __wrapper_marker_local__ = None
    
        try:
            return func(*args, **kwds)

        except Exception as e:
            tombstone(e)
            # Who am I?
            pid = f'pid{os.getpid()}'

            # First order of business: create a dump file. The file will be under
            # $PWD with today's ISO date string as the dir name.
            new_dir = os.path.join(os.getcwd(), now_as_string()[:10])
            make_dir_or_die(new_dir)

            # The file name will be the pid (possibly plus something like "A" if this
            # is the second time today this pid has failed).
            candidate_name = os.path.join(new_dir, pid)
            
            tombstone(f"writing dump to file {candidate_name}")

            with open(candidate_name, 'a') as f:
                with contextlib.redirect_stdout(f):
                    # Protect against further failure -- log the exception.
                    try:
                        e_type, e_val, e_trace = sys.exc_info()
                    except Exception as e:
                        tombstone(e)

                    print(f'Exception raised {e_type}: "{e_val}"')
                    
                    # iterate through the frames in reverse order so we print the
                    # most recent frame first
                    for i, frame_info in enumerate(inspect.getinnerframes(e_trace)):
                        f_locals = frame_info[0].f_locals
                
                        # if there's a local variable named __wrapper_marker_local__, we assume
                        # the frame is from a call of this function, 'wrapper', and we skip
                        # it. The problem happened before the dumping function was called.
                        if '__wrapper_marker_local__' in f_locals: continue

                        print(f'\nFRAME {i}: ' + '>'*i)
                        # log the frame information. A little unreadable as an f-string.
                        print('\n**File <{}>, line# {}, in function {}()\n    {}'.format(
                            frame_info[1], frame_info[2], frame_info[3], frame_info[4][0].lstrip()
                            ))

                        # log every local variable of the frame
                        for k in sorted(f_locals.keys()):
                            try:
                                print(f'    {k} = {f_locals[k]}')
                            except:
                                pass

                    print('\n')

    return wrapper

