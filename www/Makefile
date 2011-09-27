#
CONV 	= "./html.py"

FTR_PAGES := csd.html features.html gui.html nonroot.html
START_PAGES := building.html connecting.html manual.html started.html vpnc-script.html 
MAIN_PAGES := changelog.html download.html index.html packages.html platforms.html
TARGETS	= $(FTR_PAGES) $(START_PAGES) $(MAIN_PAGES)

all: $(TARGETS)

$(TARGETS): %.html: %.xml inc/*.tmpl menu1.xml
	$(CONV) -f $< || (rm $@; exit 1)

clean:
	rm -f $(TARGETS) openconnect.8.inc

$(FTR_PAGES): menu2-features.xml
$(START_PAGES): menu2-started.xml
$(MAIN_PAGES): menu2.xml

manual.html: openconnect.8.inc
openconnect.8.inc: ../openconnect.8
	groff -t -K UTF-8 -mandoc -Txhtml $^ | sed -e '1,/<body>/d' -e '/<\/body>/,$$d' > $@
