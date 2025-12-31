# Makefile for lib directory - builds klib.a static library

LIBDIR := .
INCDIR := ../include
BUILDDIR := ../build
LIBOBJDIR := $(BUILDDIR)/libobj
LIBDEPDIR := $(BUILDDIR)/libdeps

CC ?= gcc
CFLAGS_BASE := -static -D__KERNEL__ -DCONFIG_FUNCTION_ALIGNMENT=0 -Wall -Wextra -Werror -Wundef -Wstrict-prototypes -Wno-pointer-sign \
               -Wno-trigraphs -fno-strict-aliasing -fno-common -Wno-type-limits\
               -Werror-implicit-function-declaration -Wno-format-security \
               -Wno-unused-parameter -Wno-sign-compare -std=gnu11 -I$(INCDIR) \
	       -DCONFIG_XARRAY_MULTI

SANITIZER_FLAGS := -g -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -fsanitize=leak -fsanitize-undefined-trap-on-error
ifndef RELEASE
    CFLAGS := $(CFLAGS_BASE) -O0 -g -DDEBUG -fno-omit-frame-pointer $(SANITIZER_FLAGS)
    BUILD_TYPE := debug
    BUILDCONFIG := $(BUILDDIR)/.debug
else
    CFLAGS := $(CFLAGS_BASE) -O2 -g -DNDEBUG
    BUILD_TYPE := release
    BUILDCONFIG := $(BUILDDIR)/.release
endif

ifdef MEM_PROFILE
    CFLAGS += -DBCF_MEM_PROFILE
endif

Q := $(if $(filter 1,$(V)),,@)

# Find all C source files in the lib directory
LIB_SOURCES := $(wildcard $(LIBDIR)/*.c)
LIB_OBJECTS := $(LIB_SOURCES:$(LIBDIR)/%.c=$(LIBOBJDIR)/%.o)
LIB_DEPENDS := $(LIB_SOURCES:$(LIBDIR)/%.c=$(LIBDEPDIR)/%.d)

# Static library target
LIB_TARGET := $(BUILDDIR)/klib.a

AR ?= ar
RANLIB ?= ranlib

.PHONY: all clean help

all: $(LIB_TARGET)

$(LIB_TARGET): $(LIB_OBJECTS) $(BUILDCONFIG) | $(BUILDDIR)
	@echo "  AR      $@"
	$(Q)$(AR) rcs $@ $(LIB_OBJECTS)
ifneq ($(RANLIB),)
	@echo "  RANLIB  $@"
	$(Q)$(RANLIB) $@
endif

$(LIBOBJDIR)/%.o: $(LIBDIR)/%.c $(BUILDCONFIG) | $(LIBOBJDIR) $(LIBDEPDIR)
	@echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS) -MMD -MP -MF $(LIBDEPDIR)/$*.d -c $< -o $@

# Build configuration markers
$(BUILDDIR)/.debug: | $(BUILDDIR)
	@touch $@
	$(Q)rm -f $(BUILDDIR)/.release

$(BUILDDIR)/.release: | $(BUILDDIR)
	@touch $@
	$(Q)rm -f $(BUILDDIR)/.debug

$(BUILDDIR) $(LIBOBJDIR) $(LIBDEPDIR):
	$(Q)mkdir -p $@

clean:
	$(Q)rm -rf $(LIBOBJDIR) $(LIBDEPDIR) $(LIB_TARGET)

help:
	@echo "lib Makefile - Build klib.a static library"
	@echo
	@echo "Targets:"
	@echo "  all                    Build klib.a library"
	@echo "  clean                  Clean build files"
	@echo "  help                   Show this help"
	@echo
	@echo "Variables:"
	@echo "  DEBUG=1    Debug build"
	@echo "  CC=clang   Compiler"
	@echo "  AR=ar      Archiver"
	@echo "  RANLIB=ranlib Archive indexer"
	@echo "  V=1        Verbose output"

-include $(LIB_DEPENDS)

.SUFFIXES:
.DELETE_ON_ERROR:
