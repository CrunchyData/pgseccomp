MODULE_big = pgseccomp
OBJS = pgseccomp.o $(WIN32RES)

EXTENSION = pgseccomp
DATA = pgseccomp--1.0.sql get_syscalls.sh
PGFILEDESC = "pgseccomp - provide seccomp syscall filtering"

REGRESS = pgseccomp
REGRESS_OPTS = --temp-config=$(top_srcdir)/contrib/pgseccomp/pgseccomp.conf

SHLIB_LINK += -lseccomp

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pgseccomp
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
