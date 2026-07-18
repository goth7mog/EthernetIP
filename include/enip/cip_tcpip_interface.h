#ifndef ENIP_CIP_TCPIP_INTERFACE_H
#define ENIP_CIP_TCPIP_INTERFACE_H

/* TCP/IP Interface Object (CIP class 0xF5) - required by every EtherNet/IP
 * device; reports basic network configuration (here: static placeholder
 * values, since this demo doesn't manage real interface configuration). */
void cip_tcpip_interface_register(void);

#endif /* ENIP_CIP_TCPIP_INTERFACE_H */
