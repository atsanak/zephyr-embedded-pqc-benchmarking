# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
#
# Build the pqcp_ct_insn QEMU TCG plugin as a host shared object.
#
# QEMU_PLUGIN_INC must point at the directory holding qemu-plugin.h (inside
# the Zephyr SDK: hosttools/opt/qemu/include). GLIB_CFLAGS is auto-detected
# via pkg-config when available. On macOS the plugin resolves qemu_plugin_*
# symbols from the QEMU host binary at load time (-undefined dynamic_lookup).

QEMU_PLUGIN_INC ?= /usr/include
GLIB_CFLAGS ?= $(shell pkg-config --cflags glib-2.0 2>/dev/null)

CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -fPIC
INCLUDES = -I$(QEMU_PLUGIN_INC) $(GLIB_CFLAGS)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
PLUGIN_EXT := dylib
LDFLAGS := -shared -Wl,-undefined,dynamic_lookup
else
PLUGIN_EXT := so
LDFLAGS := -shared
endif

PLUGIN := libpqcp_ct_insn.$(PLUGIN_EXT)

all: $(PLUGIN)

$(PLUGIN): src/ct_insn_plugin.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) $< -o $@

clean:
	rm -f $(PLUGIN)

.PHONY: all clean
