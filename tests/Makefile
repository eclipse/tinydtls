top_builddir:=..
top_srcdir:=..

SOURCES:= netq-test.c dsrv-test.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
PROGRAMS:= $(patsubst %.c, %, $(SOURCES))
HEADERS:=
CFLAGS:=-Wall -pedantic -std=c99 -g -O2 -I$(top_srcdir)
LDFLAGS:=-L$(top_builddir)
LDLIBS:=-lnetutil
DISTDIR=$(top_builddir)/$(package)
SUBDIRS:=
FILES:=Makefile.in $(SOURCES) $(HEADERS)

.PHONY: all dirs clean distclean .gitignore doc

.SUFFIXES:
.SUFFIXES:      .c .o

all:	$(PROGRAMS) dirs

check:	
	echo DISTDIR: $(DISTDIR)
	echo top_builddir: $(top_builddir)

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
