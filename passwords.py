#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick and Dirty password generator.
"""

# Credits
__author__ = 'George Flanagin'
__copyright__ = 'Copyright 2017, University of Richmond'
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
    start_time = time.time()
    ops = 0
    rejects = 0
    well_known_lists = []
    for listname in glob.glob(my_args.lists):
        with open(listname, 'r') as f:
            x = f.read().split()
            well_known_lists.append((dict.fromkeys(x), math.log(len(x), 2)))

    well_known_lists.sort(key=lambda z:z[1])
    well_known_lists_read = time.time()

    passwords = []

    with open(my_args.words) as f:
        words = set(f.read().split())
    big_list_read = time.time()

    try:
        word_bits = math.log(len(words),2)
    except:
        word_bits = 0

    # Make a list of the sources so that we can randomly
    # choose a source and then randomly choose something within
    # the source.
    sources = []

    if len(words): sources.append((words, word_bits))
    sources.append(
        (set(string.ascii_letters), math.log(len(string.ascii_letters),2))
        )
    sources.append(
        (set(string.digits), math.log(len(string.digits),2))
        )
    sources.append(
        (set(string.punctuation), math.log(len(string.punctuation),2))
        )
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
            # rare than the rarity of the strangest word in the dictionary.
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
            passwords.append((make_safe(password,my_args.alphabet), 
                entropic_bits, timer.lap()-timer.start()))


    done_time = time.time()
    print('\n{} selection operations, with {} rejected passwords considered.\n'.format(
            ops, rejects))

    print('{} seconds creating passwords.'.format(round(done_time - sources_built,2)))

    return passwords
            

def do_help() -> None:
    """
    Usage: passwords [opts]

    Note that this is version 2, with some more sane estimates of 
    password guessability using information about the most common words
    in English.

    Options are:

        -? / --help : you are reading it.
        -a / --alphabet : allowed chars in password, defaults to quite
        -b / --bits : bits of "entropy" required in each password. YES YES
            I know this is not even sort of what is meant by 'entropy' in
            physics, but I also know the word has taken root and it is
            a measure of like, like something. Whatever. Actually. 
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


    953 selection operations, with 21 rejected passwords considered.

    4.62 seconds creating passwords.

    Passwords generated by using the following options:

      --alphabet abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=!~-? --bits 50 --guesses 1 --h False --lists /home/george/passwordgenerator/wordlist*txt --max-length 30 --min-length 16 --number 10 --words /usr/share/dict/words

         :: Password                        :: Len ::   Bits ::       Days
    =================+=========+=========+=========+=========+======================
       0 :: iNLinducting7/a5NQp             ::  19 ::   50.1 ::         14
       1 :: brightsmithV!Mor=o8lo           ::  21 ::   50.4 ::         17
       2 :: vpseudotetramerousvyvVI2v=6C    ::  28 ::   53.0 ::        108
       3 :: 9g+5fp4!depressibLeoDM          ::  22 ::   53.5 ::        144
       4 :: DLh6ADSR93Fpy396                ::  16 ::   53.4 ::        141
       5 :: NDspathousN~241jw33             ::  19 ::   50.4 ::         17
       6 :: =up798!giLt-edgeEwarmakings=z   ::  29 ::   53.0 ::        108
       7 :: spexNd30-Kacoadamite241m=       ::  25 ::   54.4 ::        277
       8 :: yuIB3B9ZirrepressibLy47~        ::  24 ::   51.1 ::         28
       9 :: 0SxbLunimmersedo9cAN            ::  20 ::   50.1 ::         14
         
    """
    print(do_help.__doc__)
    sys.exit(os.EX_OK)


if __name__ == "__main__":
    default_location = os.environ.get('PWD') + os.sep + 'wordlist*txt'

    parser = argparse.ArgumentParser()
    parser.add_argument('-?', '--h', action='store_true')
    parser.add_argument('-a', '--alphabet', type=str, 
        default=default_alphabet)
    parser.add_argument('-b', '--bits', type=int, default=50)
    parser.add_argument('-g', '--guesses', type=int, default=1)
    parser.add_argument('-l', '--lists', type=str, default=default_location)
    parser.add_argument('-n', '--number', type=int, default=10)
    parser.add_argument('-w', '--words', type=str, 
        default=dictionary_location)
    parser.add_argument('-x', '--max-length', type=int, default=40)
    parser.add_argument('-z', '--min-length', type=int, default=16)
    my_args = parser.parse_args()
    if my_args.h: do_help()
    passwords = password_gen(my_args)

    print("\nPasswords generated by using the following options:\n")
    opt_string = ' '
    for _ in sorted(vars(my_args).items()):
        opt_string += " --"+ _[0].replace("_","-") + " " + str(_[1])
    print(opt_string + "\n")

    print(" :: ".join([
        '    ',
        'Password'.ljust(my_args.max_length+1),
        'Len',
        'Bits'.rjust(6),
        'Days'.rjust(10),
        'CPU sec'.rjust(10)
        ]))
    print("=================+=========+=========+=========+=========+====================================")
    for i in range(0, len(passwords)):
        p = passwords[i]
        print(" :: ".join([
            str(i).rjust(4), 
            p[0].ljust(my_args.max_length+1), 
            str(len(p[0])).rjust(3),
            str(round(p[1],1)).rjust(6), 
            str(round(math.pow(2,p[1])/(my_args.guesses*(10**9)*86400))).rjust(10),
            str(round(p[2],3)).rjust(10)
            ]))
else:
    print('password_gen compiled')
