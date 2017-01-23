GIT_LATEST_TAG=$(shell git describe --abbrev=0 --tags)
GIT_SHORT_COMMIT_ID = $(shell git log --pretty=format:'%h' -n 1)
VERSION = $(GIT_LATEST_TAG)+$(GIT_SHORT_COMMIT_ID)
PWD = $(shell pwd)
PHP = $(shell php -v >/dev/null 2>&1 && echo OK || echo NOK)
PHP_MCRYPT  = $(shell ./php -m 2>/dev/null | grep -i mcrypt  >/dev/null 2>&1 && echo OK || echo NOK)
PHP_CURL    = $(shell ./php -m 2>/dev/null | grep -i curl    >/dev/null 2>&1 && echo OK || echo NOK)
PHP_JSON    = $(shell ./php -m 2>/dev/null | grep -i json    >/dev/null 2>&1 && echo OK || echo NOK)
PHP_OPENSSL = $(shell ./php -m 2>/dev/null | grep -i openssl >/dev/null 2>&1 && echo OK || echo NOK)
PLATFORM    = $(shell ./get_platform.sh)

ifeq ($(PHP), NOK)
$(error Error: you must install php-cli)
endif
ifeq ($(PHP_MCRYPT), NOK)
$(error Error: Missing php 'mcrypt' module and there is no support for your platform: "$(PLATFORM)")
endif
ifeq ($(PHP_CURL), NOK)
$(error Error: Missing php 'curl' module and there is no support for your platform: "$(PLATFORM)")
endif
ifeq ($(PHP_JSON), NOK)
$(error Error: Missing php 'json' module and there is no support for your platform: "$(PLATFORM)")
endif
ifeq ($(PHP_OPENSSL), NOK)
$(error Error: Missing php 'openssl' module and there is no support for your platform: "$(PLATFORM)")
endif

all: install

doc:
	sed "s/^PROJECT_NUMBER.*/PROJECT_NUMBER = ${VERSION}/;" chef-certs.doxyfile > temp.doxyfile
	\rm -rf html man debug.txt
	doxygen temp.doxyfile
	\rm -f temp.doxyfile

install: install-composer install-composer-packages install-chef-certs

update: update-git install-composer-packages install-chef-certs
	@echo
	
update-git:
	git pull

install-composer:
	./php composer >/dev/null 2>&1 || curl -sS https://getcomposer.org/installer | ./php -- --filename=composer --install-dir=.

install-composer-packages:
	./php composer self-update
	./php composer install

install-chef-certs:
	@if sudo -n false 2>/dev/null; then echo; echo "Please enter admin password (root)"; sudo echo; fi
	chmod a+x chef-certs.php
	sudo ln -sf $(PWD)/chef-certs /usr/local/bin/chef-certs
	@printf "\nRun:\n  chef-certs\n\n"

clean:
	\rm -rf composer composer.lock debug.txt html man vendor update_check
