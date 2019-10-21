#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick and Dirty password generator.
"""
import typing
from   typing import *



# Credits
__author__ = 'George Flanagin'
__copyright__ = 'Copyright 2019'
__credits__ = None
__version__ = '1.0'
__maintainer__ = 'George Flanagin'
__email__ = 'gflanagin@richmond.edu'
__status__ = 'Working Prototype'
__required_version__ = (3, 5)


# These are system packages, and there are no python environments
# that do not have them present.
import argparse
import glob
import math
import os
import platform
import random
import string
import sys
import time

import numpy

from   gkfdecorators import show_exceptions_and_frames as trap
import stopwatch

if sys.version_info < __required_version__:
    print('You need Python 3.5+ to run this program.')
    sys.exit(os.EX_SOFTWARE)

default_alphabet = string.ascii_letters + string.digits + '/+=!~-?'

where_am_i = platform.system()
if where_am_i == 'Linux':
    dictionary_location = '/usr/share/dict/words'
elif where_am_i == 'Darwin':
    dictionary_location = '/usr/share/dict/web2'
else:
    dictionary_location = ''


def load_dict(s:str) -> set:
    timer = stopwatch.Stopwatch()
    start_time = timer.start()
    with open(s) as f:
        w = set(f.read().split())
    timer.stop()
    print("dictionary loaded in {} seconds.".format(round(timer.stop() - start_time, 3)))
    return w

words = load_dict(dictionary_location) if dictionary_location else set()


@trap
def decomp(s:str, debug:bool=False) -> tuple:
    """
    Decompose a string into the largest dictionary fragments
    based on the dictionary we have available. Note that the
    data structure shown here is not particularly fast or 
    efficient with space, but it is good for being printable
    and being able to see what's going on.
    """
    dimension = len(s)

    # Assume the worst.
    t = numpy.full((dimension, dimension), 0, dtype=numpy.ubyte)

    # print(s)
    for i in range(0, dimension):
        for shredlen in range(2, dimension-i+1):
            shred = s[i:i+shredlen]
            if shred in words:
                for x in range(shredlen):
                    t[i, i+x] += 1

    # print("  "+" ".join(list(s)))
    if debug: print(t)       

    row_sums = numpy.zeros(dimension, dtype=numpy.ubyte)
    column_sums = numpy.zeros(dimension, dtype=numpy.ubyte)
    for i in range(0, dimension):
        row_sums[i] = numpy.sum(t[i,:])
        column_sums[i] = numpy.sum(t[:,i])

    if debug: print("Column sums: {}".format(tuple(column_sums)))
    fragments = []
    i = 0
    while i < dimension:
        run_len = row_sums[i]
        if not run_len: 
            fragments.append(s[i])
            i+=1
            continue
        fragments.append(s[i:i+run_len])
        i += run_len

    return fragments, column_sums


def make_safe(s:str,a:str) -> str:
    """
    UR's experience is that lower case ells and cap O create problems.
    Swap l for L and O for o, and then swap anything not in the
    allowed alphabet for something that is. Note that this substitution
    does not meaningfully change anything -- it's a random exchange.
    """
    s = s.replace('l','L')
    s = s.replace('O', 'o')
    for i in range(0, len(s)):
        if s[i] not in a:
            s = s.replace(s[i], random.choice(a))

    return s


def password_gen(my_args:argparse.Namespace) -> list:
    """
    Generate passwords and estimate their unlikeliness (if that is even
    a word). 
    """
    global words    

    start_time = time.time()
    ops = 0
    rejects = 0
    well_known_lists = [(dict.fromkeys(list(string.digits)),math.log2(10))]
    for listname in glob.glob(my_args.lists):
        with open(listname, 'r') as f:
            x = f.read().split()
            well_known_lists.append((dict.fromkeys(x), math.log2(len(x))))

    well_known_lists.sort(key=lambda z:z[1])
    well_known_lists_read = time.time()

    passwords = []

    big_list_read = time.time()

    try:
        word_bits = math.log2(len(words))
    except:
        word_bits = 0

    # Make a list of the sources so that we can randomly
    # choose a source and then randomly choose something within
    # the source.
    sources = []

    if len(words): sources.append((words, word_bits))
    sources.append(
        (set(string.ascii_letters), math.log2(len(string.ascii_letters)))
        )
    sources.append(
        (set(string.digits), math.log2(len(string.digits)))
        )
    sources.append(
        (set(string.punctuation), math.log2(len(string.punctuation)))
        )
    alphabet_bits = math.log2(len(my_args.alphabet))
    alphaonly_bits = math.log2(26)
    sources_built = time.time()
    timer = stopwatch.Stopwatch()
    fmt = "{:<" + "{}".format(my_args.max_length) + "} | {:>6}"

    for i in range(0, my_args.number):
        password = ''
        entropic_bits = 0.0
        
        # We need a password that is long enough and improbable enough...
        while (entropic_bits < my_args.bits or len(password) < my_args.min_length):

            # Note that we need the index, otherwise we would do a random.choice()
            # on the sources.
            ops += 1
            target_index = random.randrange(0,len(sources))
            target = sources[target_index]
            ops += 1
            ammendment = random.sample(target[0],1)[0]
            # If the choice is a 'word,' then there is some chance it is less
            # rare than the rarity of the least common word in the dictionary.
            if target_index == 0:
                for _ in well_known_lists:
                    ops += 1
                    if ammendment in _[0]: 
                        entropic_bits += _[1]
                        break;
                else:
                    entropic_bits += word_bits    
            else:
                entropic_bits += target[1]
            password += ammendment
    
            # Check to see if a password is too long.
            if len(password) >= my_args.max_length:
                password, entropic_bits = '', 0
                rejects += 1

        else:
            decomp_bits = 0.0
            shreds, column_sums = decomp(password, my_args.debug)        
            for shred in shreds:
                lookup_bits = [ word_list[1] for word_list in well_known_lists 
                    if shred in word_list[0] ]
                lookup_bits.append(len(shred)*alphaonly_bits)
                lookup_bits.append(word_bits)
                decomp_bits += min(lookup_bits)
            
            entropic_ratio = decomp_bits/entropic_bits
            passwords.append(
                (make_safe(password,my_args.alphabet), 
                entropic_bits, 
                timer.lap()-timer.start(), 
                entropic_ratio,
                len(password)/sum(column_sums)))


    done_time = time.time()
    print('\n{} branches, with {} branches pruned.\n'.format(ops, rejects))

    print('{} seconds creating passwords.'.format(round(done_time - sources_built,2)))

    return passwords
            

def do_help() -> None:
    """
    Usage: passwords [opts]

    "We have the best passwords."

            -- Donald J. Trump

    Options are:

        -? / --help : you are reading it.
        -a / --alphabet : allowed chars in password, defaults to quite
        -b / --bits : bits of "entropy" required in each password. YES YES
            I know this is not even sort of what is meant by 'entropy' in
            physics, but I also know the word has taken root and it is
            a measure of like, like something. Whatever. Actually. 
        -d / --debug : provide some mostly not-useful stats while running.
        -g / --guesses : a scaling factor for billion (10^9) guesses per second
            for scaling the estimate of brute force cracking. This value
            is used to figure the number of days required for the 
            password to show up in a list of passwords used in a cracking
            attempt.
        -l / --lists : location of the 'well known words' lists. This should
            be a wildcard directory/filename. The default value is 
            $PWD/wordlist*txt. The lists are assumed to be a filter
            (math meaning) on the smallest list. 
        -n / --number : how many passwords do you want? defaults to 10.
        -w / --words : location of the dictionary file.
        -x / --max-length : how long can they be? defaults to 40.
        -z / --min-length : how long must each password be? defaults to 16.
            a few of the printable characters.

    Prints the options and a list of passwords. Example shown below.


288 branches, with 0 branches pruned.

1.63 seconds creating passwords.

Passwords generated by using the following options:

  --alphabet abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=!~-? --bits 50 --debug False --guesses 1 --h False --lists /home/george/python.programming/passwordgenerator/wordlist*txt --max-length 40 --min-length 16 --number 12 --words /usr/share/dict/words

     :: Password                                  :: Len ::   Bits ::      Days ::    CPU sec
====================================================================================================
   0 :: osteadfastnessesspring-Lockchibchan       ::  35 ::   61.3 :: 3.324e+04 ::      0.209
   1 :: WScEYFVunLikeLiness                       ::  19 ::   51.8 :: 4.460e+01 ::       0.07
   2 :: churchinesskuabashedLyJ                   ::  23 ::   51.8 :: 4.684e+01 ::      0.139
   3 :: cWSECNAVAustrogaean4                      ::  20 ::   52.5 :: 7.205e+01 ::      0.216
   4 :: overcreduLousness0Fitzpat3c               ::  27 ::   50.5 :: 1.801e+01 ::      0.139
   5 :: LemassErnJ6565EfruitLet                   ::  23 ::   74.5 :: 3.166e+08 ::      0.139
   6 :: BLoxbergbpKuehn6                          ::  16 ::   50.5 :: 1.801e+01 ::      0.139
   7 :: 5u?jL0?tarsadenitis                       ::  19 ::   49.0 :: 6.598e+00 ::       0.07
   8 :: 2-8peripLasticgADC                        ::  18 ::   49.0 :: 6.598e+00 ::      0.139
   9 :: HktopchromeHgneoLogies                    ::  22 ::   56.5 :: 1.218e+03 ::      0.158
  10 :: -AIautonomouss662                         ::  17 ::   47.6 :: 2.538e+00 ::       0.07
  11 :: 7pSIcosmopoLitismzLecythidaceae           ::  31 ::   62.5 :: 7.378e+04 ::      0.139

    """
    print(do_help.__doc__)
    sys.exit(os.EX_OK)



def passwords_main():
    """
    Use the command line arguments, and generate some passwords. Good passwords.
    """
    global words
    default_location = os.environ.get('PWD') + os.sep + 'wordlist*txt'

    parser = argparse.ArgumentParser()
    parser.add_argument('-?', '--h', action='store_true')
    parser.add_argument('-a', '--alphabet', type=str, 
        default=default_alphabet)
    parser.add_argument('-b', '--bits', type=int, default=50)
    parser.add_argument('-d', '--debug', action='store_true', default=False)
    parser.add_argument('-g', '--guesses', type=int, default=1)
    parser.add_argument('-l', '--lists', type=str, default=default_location)
    parser.add_argument('-n', '--number', type=int, default=10)
    parser.add_argument('-w', '--words', type=str, 
        default=dictionary_location)
    parser.add_argument('-x', '--max-length', type=int, default=40)
    parser.add_argument('-z', '--min-length', type=int, default=16)
    my_args = parser.parse_args()
    if my_args.h: do_help()

    if my_args.words != dictionary_location: words = load_dict(my_args.words)

    passwords = password_gen(my_args)

    print("\nPasswords generated by using the following options:\n")
    opt_string = ' '
    for _ in sorted(vars(my_args).items()):
        opt_string += " --"+ _[0].replace("_","-") + " " + str(_[1]) + "\n"
    print(opt_string + "\n")

    print(" :: ".join([
        '    ',
        'Password'.ljust(my_args.max_length+1),
        'Len',
        'Bits'.rjust(6),
        # 'Days'.rjust(9),
        'CPU sec'.rjust(10),
        'Q1'.rjust(5),
        'Q2'.rjust(5)
        ]))
    print("="*100)
    deduction = 0
    for i in range(0, len(passwords)):
        p = passwords[i]

        print(" :: ".join([
            str(i).rjust(4), 
            p[0].ljust(my_args.max_length+1), 
            str(len(p[0])).rjust(3),
            str(round(p[1],1)).rjust(6), 
            # "{:.3e}".format(math.pow(2,p[1])/(my_args.guesses*(10**9)*86400)),
            str(round(p[2]-deduction,3)).ljust(10),
            str(round(p[-2],3)).ljust(5),
            str(round(p[-1],3)).ljust(6)
            ]))
        deduction = p[2]

if __name__ == "__main__":
    passwords_main()
else:
    print('password_gen compiled')
