#ifndef ENIP_CIP_ASSEMBLY_H
#define ENIP_CIP_ASSEMBLY_H

#include <stdint.h>
#include <stddef.h>

/* Assembly Object (CIP class 0x04) - bundles application I/O data points
 * into single blocks that are exchanged with a scanner/PLC over a Class 1
 * (cyclic) connection. This demo defines three fixed instances:
 *
 *   100 (Output, O->T): bytes the scanner/originator writes to us
 *   101 (Input,  T->O): bytes we produce and send back to the scanner
 *   102 (Config)      : zero-length configuration assembly
 *
 * A real device negotiates which instances/sizes to use via the Forward
 * Open connection path; this demo hardcodes them for simplicity (see
 * cip_connection_manager.c).
 */
#define ASM_INSTANCE_OUTPUT 100u
#define ASM_INSTANCE_INPUT 101u
#define ASM_INSTANCE_CONFIG 102u

#define ASM_OUTPUT_SIZE 4u
#define ASM_INPUT_SIZE 4u

void cip_assembly_register(void);

/* Direct accessors used by the UDP I/O loop (bypassing the generic
 * Get/Set_Attribute_Single path for simplicity and speed). */
void cip_assembly_write_output(const uint8_t *data, size_t len);
size_t cip_assembly_read_input(uint8_t *out, size_t out_cap);

/* Lets main.c update the Input assembly's live data (e.g. a demo counter). */
void cip_assembly_set_input(const uint8_t *data, size_t len);

#endif /* ENIP_CIP_ASSEMBLY_H */
