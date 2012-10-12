# Adding doxygen support
include aminclude.am

SUBDIRS = src man test doc
EXTRA_DIST = extra Doxyfile aminclude.am	acinclude.m4

# valgrind
valgrind-run:
	@echo 'Running with valgrind'
	valgrind --leak-check=full --show-reachable=yes $(top_builddir)/src/turnserver -c $(top_builddir)/extra/turnserver.conf

