SOURCES:= dsrv.c netq.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
HEADERS:=dsrv.h netq.h config.h
CFLAGS:=-Wall -pedantic -std=c99 -g -O2
DISTDIR=$(top_builddir)/$(package)
SUBDIRS:=tests
FILES:=Makefile.in configure configure.in config.h.in $(SOURCES) $(HEADERS)
LIB:=libnetutil.a
LDFLAGS:=
ARFLAGS:=cru

.PHONY: all dirs clean distclean .gitignore doc

.SUFFIXES:
.SUFFIXES:      .c .o

all:	$(LIB) dirs

check:	
	echo DISTDIR: $(DISTDIR)
	echo top_builddir: $(top_builddir)
	$(MAKE) -C tests check

dirs:	$(SUBDIRS)
	for dir in $^; do \
		$(MAKE) -C $$dir ; \
	done

$(LIB):	$(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^ 
	ranlib $@

clean:
	@rm -f $(PROGRAM) main.o $(LIB) $(OBJECTS)
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean ; \
	done

doc:	
	$(MAKE) -C doc

distclean:	clean
	@rm -rf $(DISTDIR)
	@rm -f *~ $(DISTDIR).tar.gz

dist:	$(FILES) $(SUBDIRS)
	test -d $(DISTDIR) || mkdir $(DISTDIR)
	cp $(FILES) $(DISTDIR)
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir dist; \
	done
	tar czf $(package).tar.gz $(DISTDIR)

.gitignore:
	echo "core\n*~\n*.[oa]\n*.gz\n*.cap\n$(PROGRAM)\n$(DISTDIR)\n.gitignore" >$@
