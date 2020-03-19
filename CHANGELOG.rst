##########
Change log
##########

0.2.2 (2020-03-19)
==================

- Fix decoding of dates in the ``oauth2_proxy`` session.

0.2.1 (2020-03-18)
==================

- Fix misplaced parameter when decoding tokens in the ``/auth`` route.

0.2.0 (2020-03-16)
==================

- Add ``/auth/analyze`` route that takes a token or ticket via the ``token`` POST parameter and returns a JSON analysis of its contents.
- Overhaul the build system to match other SQuaRE packages.
