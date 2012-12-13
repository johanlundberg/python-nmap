# python-nmap Makefile

VERSION=`python setup.py --version`
ARCHIVE=`python setup.py --fullname`


test:
	@python3 nmap/nmap.py

install:
	@python3 setup.py install

archive: doc
	@python3 setup.py sdist
	@echo Archive is create and named dist/$(ARCHIVE).tar.gz
	@echo -n md5sum is :
	@md5sum dist/$(ARCHIVE).tar.gz

license:
	@python3 setup.py --license

register:
	@python3 setup.py register

doc:
	@pydoc3 -w nmap/nmap.py

web:
	@echo $(VERSION) > web/python-nmap_CURRENT_VERSION.txt
	@cp dist/$(ARCHIVE).tar.gz web/
	@md5sum web/$(ARCHIVE).tar.gz > LAST_MD5
	@emacsclient -a /usr/bin/emacs22 LAST_MD5 web/index.gtm
	@rm LAST_MD5

.PHONY: web