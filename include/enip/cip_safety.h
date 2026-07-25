#ifndef ENIP_CIP_SAFETY_H
#define ENIP_CIP_SAFETY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* CIP Safety (ODVA Vol 5) - "black channel" functional-safety I/O layered
 * on top of an ordinary CIP/EtherNet-IP connection, aiming for SIL 3/PLe:
 * even though the underlying network (switches, cabling, this adapter's
 * own UDP stack) is completely untrusted, corruption, loss, duplication,
 * re-ordering, delay, or insertion of a safety message must always be
 * *detected*, and the moment it is, safety outputs must go to a safe
 * (de-energized/zero) state.
 *
 * IMPORTANT: this is an educational, NON-CERTIFIED illustration of those
 * ideas - not a conformant or compliant CIP Safety implementation. Real
 * CIP Safety differs in ways that matter for actual safety-rated hardware:
 *
 *   - It uses two standardized CRCs (CRC-S3 for the "Base Format", CRC-S5
 *     for "Extended Format") over specific polynomials; we use a single
 *     generic CRC-8 purely to demonstrate "an integrity check exists".
 *   - The real Safety Open handshake is a distinct request (carrying a
 *     Safety Segment with the Safety Network Number, SCID, target/
 *     originator safety info) inside Forward Open's connection path, not
 *     a different Connection Manager *instance*. We invented targeting
 *     Connection Manager instance 2 for "safety" purely so a test client
 *     can request one without us having to parse that real segment format.
 *   - Real CIP Safety also runs a separate periodic "Time Coordination"
 *     message exchange to bound clock drift between originator and
 *     target; we approximate that with a simple last-seen-timestamp/
 *     timeout check instead.
 *   - There is no dual/diverse hardware or software channel here - it's a
 *     single, ordinary process. Certification requires far more than
 *     protocol framing.
 *
 * What *is* faithfully illustrated: duplicated + bitwise-complemented data
 * (so a stuck/flipped bit becomes detectable), a monotonic sequence number
 * (so replay/duplication/re-ordering becomes detectable), a bounded
 * timeout derived from the connection's RPI and Timeout Multiplier (so
 * silence becomes detectable), and forcing a safe state the instant any
 * check fails - the same four pillars real CIP Safety relies on.
 */

#define SAFETY_APP_SIZE 1u /* 1 byte of application data per direction (demo) */

/* Fixed demo instance numbers, analogous to the Assembly instances used
 * for standard I/O (see cip_assembly.h), but kept separate/dedicated to
 * safety data so the two paths can never be confused with one another. */
#define SAFETY_INSTANCE_OUTPUT 200u /* O->T: scanner's safety command (e.g. "enable") */
#define SAFETY_INSTANCE_INPUT 201u  /* T->O: our safety status (e.g. "energized/OK")  */

/* Mode byte bit 0: 1 = Run, 0 = Idle (mirrors real CIP Safety's run/idle
 * concept, minus the other reserved/TBD bits it also defines). */
#define SAFETY_MODE_RUN 0x01u

/* Registers the (simplified) Safety Supervisor and Safety Validator CIP
 * objects with the router, for diagnostic Get_Attribute_Single/Reset. */
void cip_safety_register(void);

/* Encodes one safety PDU: mode(1) + data(len) + complement(len) + crc8(1).
 * Returns the number of bytes written, or 0 if out_cap is too small. */
size_t cip_safety_encode_pdu(uint8_t mode, const uint8_t *data, size_t len,
                             uint8_t *out, size_t out_cap);

/* Decodes/validates a safety PDU produced by cip_safety_encode_pdu(): checks
 * that the complement matches and the CRC matches. Returns false (and
 * leaves *mode_out/data_out untouched) if either check fails. */
bool cip_safety_decode_pdu(const uint8_t *pdu, size_t pdu_len, size_t data_len,
                           uint8_t *mode_out, uint8_t *data_out);

/* Called by the UDP I/O loop after successfully validating an incoming
 * safety PDU from the scanner - applies the received command bytes. */
void cip_safety_write_output(const uint8_t *data, size_t len);

/* Called by the UDP I/O loop to get the current bytes + mode to send back
 * to the scanner as our safety status. */
size_t cip_safety_read_input(uint8_t *out, size_t out_cap);
uint8_t cip_safety_current_mode(void);

/* Called by the UDP I/O loop whenever validation fails (bad complement/CRC)
 * or the safety timeout elapses with no valid data received: forces the
 * safety output to all-zero (safe state) and latches a fault that stays
 * set until acknowledged via the Safety Supervisor's Reset service. */
void cip_safety_note_validation_fault(void);
void cip_safety_note_timeout_fault(void);
bool cip_safety_is_faulted(void);

#endif /* ENIP_CIP_SAFETY_H */
