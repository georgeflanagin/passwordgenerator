# -*- coding: utf-8 -*-
import typing
from   typing import *

min_py = (3, 9)

###
# Standard imports, starting with os and sys
###
import os
import sys
if sys.version_info < min_py:
    print(f"This program requires Python {min_py[0]}.{min_py[1]}, or higher.")
    sys.exit(os.EX_SOFTWARE)

###
# Other standard distro imports
###
import argparse
from   collections.abc import Iterable
import contextlib
import getpass
mynetid = getpass.getuser()
import math
import string

###
# Installed libraries.
###


###
# From hpclib
###
import fileutils
from   urdecorators import trap

###
# imports and objects that are a part of this project
###


###
# Credits
###
__author__ = 'George Flanagin'
__copyright__ = 'Copyright 2023'
__credits__ = None
__version__ = 0.1
__maintainer__ = 'George Flanagin'
__email__ = ['gflanagin@richmond.edu']
__status__ = 'in progress'
__license__ = 'MIT'


class DeDict:
    @trap
    def __init__(self, alphabet:str, dictionary_files:Iterable):
        """
        alphabet -- a string containing one of each of the allowed
            characters for the strings that we will examine.

        dictionary_files -- a collection of zero or more files containing
            shreds that have more than one character.

        self.lookups -- a list of tuples. Each tuple has [0] as a dict 
            of the shreds, and [1] is the log_2(len(the dict)).
        """
        self.lookups = [ tuple( [dict.fromkeys(list(alphabet)), math.log2(len(alphabet))] ) ]
        for f in dictionary_files:
            try:
                data = tuple(fileutils.read_whitespace_file(f))
                self.lookups.append(tuple([dict.fromkeys(data), math.log2(len(data))]))
            except Exception as e:
                print(f"Failed to load {f}. {e}")
                sys.exit(os.EX_DATAERR)

        self.alphabet = self.lookups[0]


    @trap
    def dedict(self, s:str) -> tuple:
        """
        Separate a string into the longest component strings that
        are based on the contents of the known dictionaries.

        s -- A string to be decomposed.

        returns -- a Tuple(float, dict).
            The float represents the score of the string, and the 
            dict is a collection of keys that represent the component
            strings with values that represent their individual scores.

        """

        answer = {}
        eos = len(s) + 1

        start = 0
        pos = eos
        answer = {}
        while start < eos and pos>start:

            # Any one char token is "in" the dictionary.
            if pos - start == 1:
                c = s[start:start+1]
                try:
                    answer[c] = math.log2(int(c))
                except:
                    answer[c] = self.alphabet[1]
                    
                start += 1
                pos = eos
                continue

            token = s[start:pos] 
            print(f"{start=} {pos=} {token=}")

            # First up, let's see if it is a number of some kind. If this
            # is the case, then we consume the number, and move along.
            try:
                _ = int(token)
                print(f"{token} is a number")
                answer[token] = math.log2(_)
                start = pos
                pos = eos
                continue

            except: # not numeric.
                pass
    
            # Now, we look through the lookup tables.
            for d, bits in self.lookups:
                if token in d or token.lower() in d:
                    bits = min(bits, self.alphabet[1]*len(token))
                    print(f"Found {token} with {bits=}")
                    answer[token] = bits
                    start = pos
                    pos = eos
                    break

            # Shorten the token from the end.
            pos -= 1
                
        return tuple([sum(answer.values()), answer])
        

@trap
def dedict_main(myargs:argparse.Namespace) -> int:
    
    default_alphabet = string.ascii_letters + string.digits + '/+=!~-?'
    decomposer = DeDict(default_alphabet, fileutils.all_files_like("./wordlist*txt"))
    
    for word in myargs.words:
        bits, data = decomposer.dedict(word)
        list_size = 2**bits
        print(f"{word=} {list_size=} {data=}")

    return os.EX_OK


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(prog="dedict", 
        description="What dedict does, dedict does best.")

    parser.add_argument('-d', '--dict', type=str, default="/usr/share/dict/linux.words",
        help="Dictionary name.")
    parser.add_argument('-o', '--output', type=str, default="",
        help="Output file name")
    parser.add_argument('words', action='append', default=[])

    myargs = parser.parse_args()

    try:
        outfile = sys.stdout if not myargs.output else open(myargs.output, 'w')
        with contextlib.redirect_stdout(outfile):
            sys.exit(globals()[f"{os.path.basename(__file__)[:-3]}_main"](myargs))

    except Exception as e:
        print(f"Escaped or re-raised exception: {e}")

