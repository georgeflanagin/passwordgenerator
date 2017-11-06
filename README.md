# passwordgenerator
This is a one file, password generator, that works on common distros of Linux, as well as Mac OS X
It probably will work on Windows from a `git bash` console window, but I have not tried it. The
limitation for Windows is the lack of a system-wide dictionary, but this program does have the
ability to use any dictionary.

The "bits" estimate is more correctly an estimate of the smallest list
of passwords in which the generated password might appear. The source
code will reveal all... For scaling/comprehension of large numbers:

- 50 bits -> 10^15 ('quadrillion')
- 60 bits -> 10^18 ('quintillion')
- 70 bits -> 10^21 ('sextillion')

The following is the current help, with an example output.

```
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
``` 
