/* Section boundaries for libFuzzer's coverage tables on Windows (MSVC linker).
 *
 * LLVM's SanitizerCoverage puts the 8-bit counters in ".SCOV$CM" and the PC table in
 * ".SCOVP$M" and refers to __start_/__stop_ symbols around them. Normally the sanitizer
 * runtime (compiler-rt sanitizer_coverage_win_sections.cpp) defines them; without the
 * AddressSanitizer runtime (not installed with this Visual Studio) nothing does. The linker
 * sorts sections by the text after '$', so "A" lands before "M" and "Z" after it.
 *
 * As in compiler-rt: each start symbol is a uint64_t (LLVM adds 8 bytes to it, so the table
 * starts right after it), and each stop symbol is a single byte.
 *
 * Test tooling only (fuzz/): never part of UNTRACE. */
#include <stdint.h>

#pragma section(".SCOV$CA", read, write)
__declspec(allocate(".SCOV$CA")) uint64_t __start___sancov_cntrs = 0;
#pragma section(".SCOV$CZ", read, write)
__declspec(allocate(".SCOV$CZ")) __declspec(align(1)) uint8_t __stop___sancov_cntrs = 0;

#pragma section(".SCOVP$A", read)
__declspec(allocate(".SCOVP$A")) uint64_t __start___sancov_pcs = 0;
#pragma section(".SCOVP$Z", read)
__declspec(allocate(".SCOVP$Z")) __declspec(align(1)) uint8_t __stop___sancov_pcs = 0;
