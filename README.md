# passwordgenerator
This is a one file, password generator, that works on common distros
of Linux, as well as Mac OS X It probably will work on Windows from a
`git bash` console window, but I have not tried it. The limitation for
Windows is the lack of a system-wide dictionary, but this program does
have the ability to use any dictionary.

The "bits" estimate is more correctly an estimate of the smallest list
of passwords in which the generated password might appear. The source
code will reveal all... For scaling/comprehension of large numbers:

- 50 bits -> 10^15 ('quadrillion')
- 60 bits -> 10^18 ('quintillion')
- 70 bits -> 10^21 ('sextillion')

The following is the current help, with an example output.

```

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

``` 
