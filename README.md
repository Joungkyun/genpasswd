genpasswd
=========

copyright (c) 2016 JoungKyun.Kim <http://oops.org> all rights reserved.

Generate password with MD5, SHA256 or SHA512 algorithm and print stdout.

The password of genpasswd requires follow features:

  1. requires at least 9 characters
  2. support 3 classes with upper case, lower case, numeric or special character

## License

BSD-2-Clause

## Build

for the detailes, see also INSTALL documents

```bash
[root@host ~]$ cd genpasswd
[root@host genpasswd]$ ./configure
[root@host genpasswd]$ make install
```

## Usage

```bash
[root@host ~]$ genpasswd -h

Usage: genpasswd [OPTION]
       -i      given password with STDIN
       -m      Crypt method: md5 or sha256 or sha512 [default: sha512]
       -s      user define salt [default: random string]

[root@host ~]$
```

  * general usage

  ```bash
  [root@host ~]$ genpasswd
  Password:
  Retype Password:
  $6$QVUmeiHD$7SvS6dNrLTwkBCX64IrEEwUPNumFpWYRWIA2YYvAW1NkfjQ4WepbkRMEpwHhqmRaZRgs4vhqsJllm2BuhRcJv/
  [root@host ~]$
  ```

  * make m5 hash string

  ```bash
  [root@host ~]$ genpasswd -m md5
  Password:
  Retype Password:
  $1$fhO7E9to$BJ/F6xUD9x0dnusVd8v/y0
  [root@host ~]$
  ```

  * make hash strings with STDIN
  ```
  [root@host ~]$ echo 'agsfD%!@#tR' | genpasswd -i -m md5
  $1$L1vQ5gzS$G6oklT7IAhnPykApel9My0
  [root@host ~]$
  ```

## Credits
JoungKyun.Kim
