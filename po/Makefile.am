
LINGUAS = @LINGUAS@
MOFILES = $(LINGUAS:%=%.mo)
POFILES = $(LINGUAS:%=%.po)

noinst_DATA = $(MOFILES)

SUFFIXES = .mo

.po.mo:
	rm -f  && $(MSGFMT) -o $@ $<

clean-local:
	rm -f $(MOFILES)

install-data-hook: all
	linguas="$(LINGUAS)"; \
	for l in $$linguas; do \
	  dir="$(DESTDIR)$(localedir)/$$l/LC_MESSAGES"; \
	  $(mkdir_p) $$dir; \
	  echo Installing $$l.mo to $$dir/$(PACKAGE).mo ; \
	  $(INSTALL_DATA) $$l.mo $$dir/$(PACKAGE).mo; \
	done

uninstall-hook:
	linguas="$(LINGUAS)"; \
	for l in $$linguas; do \
	  file="$(DESTDIR)$(localedir)/$$l/LC_MESSAGES/$(PACKAGE).mo"; \
	  if [ -r "$$file" ]; then \
	    echo "Removing $$file"; rm -f "$$file"; \
	  fi ; \
	done

# $(PACKAGE).pot is built by a rule in the parent directory Makefile
# This rule isn't needed but is here for convenience if manually invoked
.PHONY: $(PACKAGE).pot
$(PACKAGE).pot:
	$(MAKE) -C .. po/$@

EXTRA_DIST = $(POFILES) LINGUAS
DISTCLEANFILES=$(PACKAGE).pot
