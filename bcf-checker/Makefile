# SPDX-License-Identifier: GPL-2.0-only
PROJECT_NAME := bcf-checker
VERSION := 0.0.1

SRCDIR := .
INCDIR := include
BUILDDIR := build
OBJDIR := $(BUILDDIR)/obj
DEPDIR := $(BUILDDIR)/deps
TESTDIR := $(BUILDDIR)/tests
LIBDIR := lib

Q := $(if $(filter 1,$(V)),,@)

CC ?= clang
CFLAGS_BASE := -Wall -Wextra -Werror -Wundef -Wstrict-prototypes -Wno-sign-compare \
               -Wno-trigraphs -fno-strict-aliasing -fno-common  -Wno-type-limits \
               -Wno-unused-parameter -Wno-unused-function -Wno-override-init\
	       -Wshadow -std=gnu11 -I$(INCDIR)

ifndef RELEASE
    CFLAGS := $(CFLAGS_BASE) -O0 -g -DDEBUG -fno-omit-frame-pointer
    STRIP :=
    BUILD_TYPE := debug
    BUILDCONFIG := $(BUILDDIR)/.debug
else
    CFLAGS := -static $(CFLAGS_BASE) -O2 -DNDEBUG
    STRIP := strip --strip-all
    BUILD_TYPE := release
    BUILDCONFIG := $(BUILDDIR)/.release
endif

SANITIZER_FLAGS := -g -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -fsanitize=leak
LDFLAGS := -Wl,-z,relro -Wl,-z,now

SOURCES := $(filter-out $(wildcard $(SRCDIR)/*_test.c),$(wildcard $(SRCDIR)/*.c))
HEADERS := $(shell find $(INCDIR) -name "*.h" 2>/dev/null 2>/dev/null || true)

OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DEPENDS := $(SOURCES:$(SRCDIR)/%.c=$(DEPDIR)/%.d)

TARGET := $(PROJECT_NAME)
TEST_TARGETS := $(TEST_SOURCES:$(SRCDIR)/%.c=$(TESTDIR)/%)

# Build the kernel lib
LIB_TARGET := $(BUILDDIR)/klib.a

.PHONY: all clean format help

all: lib $(TARGET)

# Build the library first
lib: $(LIB_TARGET)

$(LIB_TARGET): | $(BUILDDIR)
	@echo "  MAKE    lib/klib.a"
	$(Q)$(MAKE) -C $(LIBDIR) all

$(TARGET): $(OBJECTS) $(LIB_TARGET) $(BUILDCONFIG) | $(BUILDDIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(LDFLAGS) -o $@ $(filter-out $(BUILDCONFIG),$^)
ifneq ($(STRIP),)
	@echo "  STRIP   $@"
	$(Q)$(STRIP) $@
endif
ifdef RELEASE
	@echo "  SIZE    $@"
	$(Q)stat -c "%s bytes" $@
	@echo "  UPX     $@"
	$(Q)if command -v upx >/dev/null 2>&1; then \
		upx --best $@; \
		echo "  SIZE    $@ (compressed)"; \
		stat -c "%s bytes" $@; \
	else \
		echo "  UPX     not found, skipping compression"; \
	fi
endif

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(BUILDCONFIG) | $(OBJDIR) $(DEPDIR)
	@echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS) -MMD -MP -MF $(DEPDIR)/$*.d -c $< -o $@

# Build configuration markers
$(BUILDDIR)/.debug: | $(BUILDDIR)
	@touch $@
	$(Q)rm -f $(BUILDDIR)/.release

$(BUILDDIR)/.release: | $(BUILDDIR)
	@touch $@
	$(Q)rm -f $(BUILDDIR)/.debug

$(BUILDDIR) $(OBJDIR) $(DEPDIR) $(TESTDIR):
	$(Q)mkdir -p $@

format:
	$(Q)if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(SOURCES) $(TEST_SOURCES); \
	else \
		echo "clang-format not found"; \
	fi

clean:
	$(Q)rm -rf $(BUILDDIR) $(TARGET)
	$(Q)$(MAKE) -C $(LIBDIR) clean

help:
	@echo "$(PROJECT_NAME) v$(VERSION) - Build System"
	@echo
	@echo "Targets:"
	@echo "  all                    Build project"
	@echo "  clean			Clean build files"
	@echo "  format          	Code analysis and formatting"
	@echo "  help			Version info and this help"
	@echo
	@echo "Variables:"
	@echo "  RELEASE=1    Release build"

-include $(DEPENDS)

.SUFFIXES:
.DELETE_ON_ERROR:
