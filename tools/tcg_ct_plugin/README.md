# QEMU instruction and memory-access evidence plugin

`pqcp_ct_insn` is a QEMU TCG plugin that counts guest instructions, loads, and
stores between two firmware marker addresses. A runner resolves the marker
symbols from the firmware ELF and passes their addresses as plugin arguments.

The output is intentionally machine-readable:

```text
PQCP_CT_INSN region=0 insns=4217 loads=803 stores=119
PQCP_CT_INSN done regions=1
```

Equal instruction and access counts across controlled inputs are stronger
regression evidence than wall-clock timing alone. They are not a formal
constant-time proof: accessed addresses, cache behavior, and other
microarchitectural effects remain outside this tool's scope.

## Build

Point `QEMU_PLUGIN_INC` at the directory containing `qemu-plugin.h`:

```bash
make -C tools/tcg_ct_plugin \
  QEMU_PLUGIN_INC=/path/to/qemu/include
```

## Load

```bash
qemu-system-x86_64 \
  -plugin tools/tcg_ct_plugin/libpqcp_ct_insn.so,begin=0x1000,end=0x1100,outfile=ct.log \
  ...
```

The actual marker addresses must come from the ELF being measured. Hard-coding
addresses from another build invalidates the evidence.
