ENTRY(probe_start)
MEMORY { sram (rwx) : ORIGIN = 0x4ff30000, LENGTH = 32K }
SECTIONS {
  .text : { KEEP(*(.text.start)) *(.text .text.*) *(.rodata .rodata.* .srodata*) } > sram
  .data : { *(.data .data.* .sdata*) } > sram
  .bss (NOLOAD) : { *(.bss .bss.* .sbss*) *(COMMON) } > sram
  ASSERT(. < ORIGIN(sram) + LENGTH(sram) - 4096, "probe exceeds RAM budget")
  _stack_top = ORIGIN(sram) + LENGTH(sram);
}
