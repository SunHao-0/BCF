PROJECT_NAME := bcf-checker
VERSION := 1.0.0

SRCDIR := .
INCDIR := include
BUILDDIR := build
OBJDIR := $(BUILDDIR)/obj
DEPDIR := $(BUILDDIR)/deps
TESTDIR := $(BUILDDIR)/tests
LIBDIR := lib

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
TEST_CFLAGS := $(CFLAGS) -DTEST_BUILD $(SANITIZER_FLAGS) \
               -Wno-unused-variable -Wno-unused-but-set-variable \
               -Wno-unused-function
TEST_LDFLAGS := $(SANITIZER_FLAGS)

LDFLAGS := -Wl,-z,relro -Wl,-z,now

Q := $(if $(filter 1,$(V)),,@)

SOURCES := $(filter-out $(wildcard $(SRCDIR)/*_test.c),$(wildcard $(SRCDIR)/*.c))
TEST_SOURCES := $(wildcard $(SRCDIR)/*_test.c)
HEADERS := $(shell find $(INCDIR) -name "*.h" 2>/dev/null 2>/dev/null || true)

OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TEST_OBJECTS := $(TEST_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DEPENDS := $(SOURCES:$(SRCDIR)/%.c=$(DEPDIR)/%.d)
TEST_DEPENDS := $(TEST_SOURCES:$(SRCDIR)/%.c=$(DEPDIR)/%.d)

TARGET := $(PROJECT_NAME)
TEST_TARGETS := $(TEST_SOURCES:$(SRCDIR)/%.c=$(TESTDIR)/%)

# Library target
LIB_TARGET := $(BUILDDIR)/klib.a

TOOLS := sparse clang-format ctags bear upx

.PHONY: all clean distclean help
.PHONY: check format format-check tags compile_commands.json version
.PHONY: test test-all checkdeps check-tools lib

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

$(OBJDIR)/%_test.o: $(SRCDIR)/%_test.c $(BUILDCONFIG) | $(OBJDIR) $(DEPDIR)
	@echo "  CC      $@ (test)"
	$(Q)$(CC) $(TEST_CFLAGS) -MMD -MP -MF $(DEPDIR)/$*.d -c $< -o $@

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

test: test-all

test-all: $(TEST_TARGETS)
	@echo "Running tests..."
	$(Q)for test in $^; do \
		echo "  RUN     $$(basename $$test)"; \
		$$test || exit 1; \
	done
	@echo "All tests passed!"

# For test builds, create a version of bcf_checker.c with all 'static' removed
BCF_CHECKER_TESTLIB_C := $(BUILDDIR)/bcf_checker_testlib.c
BCF_CHECKER_OBJ := $(OBJDIR)/bcf_checker_testlib.o
BCF_CHECKER_A := $(BUILDDIR)/bcf_checker.a

$(BCF_CHECKER_TESTLIB_C): $(SRCDIR)/bcf_checker.c | $(BUILDDIR)
	@echo "  GEN     $@ (remove static)"
	$(Q)sed 's/^\s*static\b//' $< > $@

$(BCF_CHECKER_OBJ): $(BCF_CHECKER_TESTLIB_C) $(BUILDCONFIG) | $(OBJDIR) $(DEPDIR)
	@echo "  CC      $@ (testlib)"
	$(Q)$(CC) $(TEST_CFLAGS) -MMD -MP -MF $(DEPDIR)/bcf_checker_testlib.d -c $< -o $@

$(BCF_CHECKER_A): $(BCF_CHECKER_OBJ) | $(BUILDDIR)
	@echo "  AR      $@"
	$(Q)ar rcs $@ $<

# Link test executables with the testlib static library and klib.a
$(TESTDIR)/%: $(OBJDIR)/%.o $(BCF_CHECKER_A) $(LIB_TARGET) $(BUILDCONFIG) | $(TESTDIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(TEST_LDFLAGS) -o $@ $< $(BCF_CHECKER_A) $(LIB_TARGET)

$(BUILDDIR) $(OBJDIR) $(DEPDIR) $(TESTDIR):
	$(Q)mkdir -p $@

check: $(TARGET)
	$(Q)echo "  SPARSE  $(SOURCES)"; sparse $(CFLAGS) $(SOURCES) include/uapi/linux/bcf.h

format:
	$(Q)if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(SOURCES) $(TEST_SOURCES); \
	else \
		echo "clang-format not found"; \
	fi

format-check:
	$(Q)if command -v clang-format >/dev/null 2>&1; then \
		clang-format -n $(SOURCES) $(TEST_SOURCES); \
	else \
		echo "clang-format not found"; \
	fi

tags: | $(BUILDDIR)
	$(Q)if command -v ctags >/dev/null 2>&1; then \
		ctags -R $(SRCDIR) $(INCDIR) $(TEST_SOURCES) && mv tags $(BUILDDIR)/ && \
		echo "  TAGS   $(BUILDDIR)/tags"; \
	else \
		echo "ctags not found"; \
	fi

compile_commands.json: clean | $(BUILDDIR)
	$(Q)if command -v bear >/dev/null 2>&1; then \
		bear -- $(MAKE) all; \
		mv compile_commands.json $(BUILDDIR)/ && \
		echo "  DB     $(BUILDDIR)/compile_commands.json"; \
	else \
		echo "Bear not found. Install bear to generate compile_commands.json"; \
		exit 1; \
	fi

clean:
	$(Q)rm -rf $(BUILDDIR) $(TARGET)
	$(Q)$(MAKE) -C $(LIBDIR) clean

distclean: clean
	$(Q)rm -rf tags compile_commands.json

checkdeps:
	$(Q)which $(CC) >/dev/null || (echo "Error: $(CC) not found" && exit 1)
	@echo "  CC      $(CC) - OK"

check-tools:
	$(Q)for tool in $(TOOLS); do \
		if command -v $$tool >/dev/null 2>&1; then \
			echo "  $$tool   OK"; \
		else \
			echo "  $$tool   NOT FOUND"; \
		fi; \
	done

version:
	@echo "$(PROJECT_NAME) version $(VERSION)"

help:
	@echo "$(PROJECT_NAME) v$(VERSION) - Build System"
	@echo
	@echo "Targets:"
	@echo "  all                    Build project"
	@echo "  lib                    Build klib.a library"
	@echo "  clean, distclean       Clean build files"
	@echo "  check, format          Code analysis and formatting"
	@echo "  tags                   Generate navigation databases"
	@echo "  compile_commands.json  Generate clangd database (requires bear)"
	@echo "  test, test-all         Run all tests"
	@echo "  checkdeps, check-tools Dependency and tool checks"
	@echo "  version, help          Version info and this help"
	@echo
	@echo "Variables:"
	@echo "  RELEASE=1    Release build"
	@echo "  CC=clang   Compiler       V=1             Verbose output"

-include $(DEPENDS) $(TEST_DEPENDS)

# Preserve test object files
.PRECIOUS: $(TEST_OBJECTS)

.SUFFIXES:
.DELETE_ON_ERROR:
