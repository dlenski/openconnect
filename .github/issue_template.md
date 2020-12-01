<!--

  Hold on a sec right there...

  => Are you having a problem with functionality of a *released* version of OpenConnect? <=

  If so, this isn't the place for it. Use the official OpenConnect mailing list instead:

    http://www.infradead.org/openconnect/mail.html

  => Are you asking for help *building* the under-development version of OpenConnect in
     this repository? <=

  THERE SHOULD BE NO REASON FOR YOU TO BUILD THIS VERSION UNLESS YOU NEED SOME FUNCTIONALITY
  THAT'S NOT IN A RELEASED VERSION, OR ARE WORKING ON DEVELOPING NEW FEATURES.

  If you really *do* want to build from this repository, please refer to what I wrote in the
  README:

    https://github.com/dlenski/openconnect/HEAD/globalprotect/README.md#installation

  This version has the exact same build dependencies as the official OpenConnect;
  modern versions of autoconf, automake, gcc, libxml, etc. Follow the
  official build instructions, or ask for help on the official mailing list:

    http://www.infradead.org/openconnect/building.html

  If you are having trouble *building* this version of OpenConnect, I am
  simply going to refer you back to the official instructions :-D

  (Unless you can demonstrate that I have somehow broken the ability to
   to build this version using the official instructions. See #9 for an example
   of this:

   https://github.com/dlenski/openconnect/pull/9 )


---------------------------------------------------------------------


  On the other hand, if you have successfully *built* this version of
  OpenConnect, and are now encountering specific, reproducible errors while
  *running* it, please continue and fill out details requested below ...

-->

# Problem description

1. I ran openconnect-gp as follows: `openconnect --protocol=gp <!-- Show other command line options here -->`
2.
3.
4.

# Operating system and openconnect-gp version

openconnect-gp version:

```
    <!-- Run "openconnect --version" and include the output here -->
```

operating system

```
    <!-- Run "uname -a" and include the output here -->
```

# GlobalProtect VPN information

```
<!--
    Run openconnect with the highest verbosity, and dump all HTTP traffic:

       openconnect --dump-http-traffic -vvvv

    Compare its output with the anonymized GlobalProtect VPN connection flow shown here:

       https://gist.github.com/dlenski/5046e5f934ac111e8d8718fc10c25703

    Include as much of the HTTP traffic as you can here. Don't forget to anonymize sensitive
    information, especially:
       - username
       - password
       - authcookie
       - ESP keys
       - external IP addresses
-->
```
