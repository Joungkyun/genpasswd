# Process this file with automake to produce Makefile.in
# Copyright (c) 2016, JoungKyun.Kim <http://oops.org>
# All rights reserved.
#
# This file is part of genpaswd
# 
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

CLEANFILES = POTFILES *.mo
EXTRA_DIST = default.pot ko.po

all:
	for i in `ls *.po | sed 's/\.po//'`; do \
		$(MSGFMT) $$i.po -o $$i.mo; \
	done

install:
	for i in `ls *.po | sed 's/\.po//'` ; do \
		$(MKDIR_P) $(DESTDIR)$(localedir)/$$i/LC_MESSAGES/ ; \
		$(INSTALL) -m644 $$i.mo $(DESTDIR)$(localedir)/$$i/LC_MESSAGES/$(PACKAGE).mo ; \
	done

pot:
	find ../ -name "*.c" > POTFILES
	$(XGETTEXT) -d default -k_ --from-code=utf-8 -s `cat POTFILES`
	mv default.po default.pot

merge:
	for i in `ls *.po`; do \
		$(MSGMERGE) -U $$i default.pot; \
		rm -f $$i~; \
	done

