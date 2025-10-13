PROJECT_NAME := bcf-checker
VERSION := 1.0.0

# SRCDIR := .
SRCDIR := $(shell pwd)
INCDIR := include
BUILDDIR := build
OBJDIR := $(BUILDDIR)/obj
DEPDIR := $(BUILDDIR)/deps
TESTDIR := $(BUILDDIR)/tests
LIBDIR := lib

CC ?= clang
CFLAGS_BASE := -D__KERNEL__ -DCONFIG_FUNCTION_ALIGNMENT=0 -Wall -Wextra -Werror -Wundef -Wstrict-prototypes -Wno-sign-compare -Wno-unused-parameter \
               -Wno-trigraphs -fno-strict-aliasing -fno-common  -Wno-type-limits -Wno-override-init\
	       -Wshadow -std=gnu11 -I$(INCDIR) -I$(SRCDIR)

LDFLAGS := -Wl,-z,relro -Wl,-z,now

SANITIZER_FLAGS := -g -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -fsanitize=leak -fsanitize-undefined-trap-on-error

ifndef RELEASE
    CFLAGS := $(CFLAGS_BASE) -O0 -g -DDEBUG -fno-omit-frame-pointer $(SANITIZER_FLAGS)
    LDFLAGS += $(SANITIZER_FLAGS)
    STRIP :=
    BUILD_TYPE := debug
    BUILDCONFIG := $(BUILDDIR)/.debug
else
    CFLAGS := -static $(CFLAGS_BASE) -O2 -DNDEBUG -Wframe-larger-than=2024
    STRIP := strip --strip-all
    BUILD_TYPE := release
    BUILDCONFIG := $(BUILDDIR)/.release
endif

TEST_CFLAGS := $(CFLAGS) -DTEST_BUILD $(SANITIZER_FLAGS) \
               -Wno-unused-variable -Wno-unused-but-set-variable \
               -Wno-unused-function
TEST_LDFLAGS := $(SANITIZER_FLAGS)


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

REWRITES_DIR := rewrites
BV_REWRITES := $(wildcard $(REWRITES_DIR)/bv-rewrites*)
BOOL_REWRITES := $(wildcard $(REWRITES_DIR)/boolean-rewrites*)
BUILTIN_REWRITES := $(wildcard $(REWRITES_DIR)/builtin-rewrites*)
UF_REWRITES := $(wildcard $(REWRITES_DIR)/uf-rewrites*)
REWRITE_HEADER := $(SRCDIR)/bcf_rewrites.h

TOOLS := sparse clang-format ctags bear upx

.PHONY: all clean distclean help gen-rewrites
.PHONY: check format format-check tags compile_commands.json version
.PHONY: test test-all checkdeps check-tools lib

all: lib $(TARGET)

gen-rewrites:
	$(Q)echo "// AUTOMATICALLY GENERATED, DO NOT EDIT" > $(REWRITE_HEADER)
	$(Q)python3 $(REWRITES_DIR)/convert/mk_bcf_rewrites.py --rewrites_file $(BUILTIN_REWRITES) --no-enum-variants >> $(REWRITE_HEADER)
	$(Q)python3 $(REWRITES_DIR)/convert/mk_bcf_rewrites.py --rewrites_file $(UF_REWRITES) --no-enum-variants >> $(REWRITE_HEADER)
	$(Q)python3 $(REWRITES_DIR)/convert/mk_bcf_rewrites.py --rewrites_file $(BOOL_REWRITES) --no-enum-variants >> $(REWRITE_HEADER)
	$(Q)python3 $(REWRITES_DIR)/convert/mk_bcf_rewrites.py --rewrites_file $(BV_REWRITES) --no-enum-variants >> $(REWRITE_HEADER)
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

$(BCF_CHECKER_TESTLIB_C): $(SRCDIR)/bcf_checker.c $(REWRITE_HEADER) | $(BUILDDIR)
	@echo "  GEN     $@ (remove static)"
	$(Q)sed 's/^\s*static\b//' $< > $@
	$(Q)cp $(REWRITE_HEADER) $(BUILDDIR)

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

SOURCES_CHECK := $(filter-out $(REWRITE_HEADER),$(SOURCES))
check: $(TARGET)
	$(Q)echo "  SPARSE  $(SOURCES)"; sparse $(CFLAGS) $(SOURCES_CHECK) include/uapi/linux/bcf.h

SOURCES_FORMAT := $(filter-out $(REWRITE_HEADER),$(SOURCES) $(TEST_SOURCES))
format:
	$(Q)if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(SOURCES_FORMAT); \
	else \
		echo "clang-format not found"; \
	fi

format-check:
	$(Q)if command -v clang-format >/dev/null 2>&1; then \
		clang-format -n $(SOURCES_FORMAT); \
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
