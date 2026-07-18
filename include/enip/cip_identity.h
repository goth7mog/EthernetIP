#ifndef ENIP_CIP_IDENTITY_H
#define ENIP_CIP_IDENTITY_H

#include <stdint.h>
#include <stdbool.h>

/* Identity Object (CIP class 0x01) - every EtherNet/IP device must
 * implement instance 1 of this object. It is what shows up when a client
 * does a "Browse" / ListIdentity scan, and its attributes are the classic
 * "who are you" fields: vendor, device type, product code/revision,
 * status, serial number and product name. */

void cip_identity_register(void);

/* Called by the Connection Manager when a Class 1 I/O connection opens or
 * closes, so Identity's Status attribute (bit 0 = "owned") reflects reality
 * the way a real adapter's would. */
void cip_identity_set_owned(bool owned);

/* Convenience accessors used by encapsulation code (ListIdentity reply, and
 * the future Identity item of ListServices) to fetch the same data the CIP
 * object exposes, without going through a full CIP request round-trip. */
uint16_t cip_identity_vendor_id(void);
uint16_t cip_identity_device_type(void);
uint16_t cip_identity_product_code(void);
uint8_t cip_identity_revision_major(void);
uint8_t cip_identity_revision_minor(void);
uint16_t cip_identity_status(void);
uint32_t cip_identity_serial_number(void);
const char *cip_identity_product_name(void);

#endif /* ENIP_CIP_IDENTITY_H */
