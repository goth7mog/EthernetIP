#ifndef ENIP_CIP_SAFETY_H
#define ENIP_CIP_SAFETY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* CIP Safety (ODVA Vol 5) - "black channel" functional-safety I/O layered
 * on top of an ordinary CIP/EtherNet-IP connection, aiming for SIL 3/PLe:
 * even though the underlying network (switches, cabling, this adapter's
 * own UDP stack) is completely untrusted. Corruption, loss, duplication,
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
 *   - There is STILL no dual/diverse *hardware* channel here - it's one
 *     process, one thread, one CPU. What's below is a SOFTWARE-ONLY
 *     simulation of the *concept* of redundancy/diversity/diagnostics: two
 *     independently-implemented checks ("Channel A"/"Channel B") that must
 *     both agree, plus a self-test that proves those checks can still
 *     detect known-bad data. A real certified device needs this same idea
 *     realized across genuinely independent execution channels (see the
 *     project README/chat history for why software-only redundancy on one
 *     CPU can't substitute for that).
 *
 * What *is* illustrated: duplicated + bitwise-complemented data (so a
 * stuck/flipped bit becomes detectable), TWO independently-coded integrity
 * checks that must both agree ("Channel A" = CRC-8, "Channel B" = a
 * differently-structured checksum + its own complement re-derivation, so a
 * bug specific to one algorithm doesn't silently pass the other), a
 * periodic self-test that exercises both channels against known-good and
 * known-bad vectors, a monotonic sequence number (replay/re-order
 * detection), a bounded timeout derived from RPI and Timeout Multiplier,
 * and forcing + latching a safe state the instant any of this fails.
 */

#define SAFETY_APP_SIZE 1u /* 1 byte of application data per direction (demo) */

/* PDU layout: mode(1) + data(len) + complement(len) + crc8(1) + checksum_b(1) */
#define SAFETY_PDU_MAX_LEN (3u + 2u * SAFETY_APP_SIZE)

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

/* Result of validating a safety PDU against BOTH independently-implemented
 * checks. See the header comment above for what "Channel A"/"Channel B"
 * mean here (a software simulation of redundancy, not real hardware). */
typedef enum {
    CIP_SAFETY_CHECK_OK = 0,
    CIP_SAFETY_CHECK_CHANNEL_A_FAULT,  /* CRC-8/complement check failed         */
    CIP_SAFETY_CHECK_CHANNEL_MISMATCH, /* Channel A passed but Channel B didn't */
} cip_safety_check_result_t;

/* Encodes one safety PDU: mode(1) + data(len) + complement(len) + Channel A
 * CRC-8(1) + Channel B checksum(1). Returns the number of bytes written, or
 * 0 if out_cap is too small. */
size_t cip_safety_encode_pdu(uint8_t mode, const uint8_t *data, size_t len,
                              uint8_t *out, size_t out_cap);

/* Decodes/validates a safety PDU produced by cip_safety_encode_pdu() against
 * two independently-implemented checks (see cip_safety_check_result_t).
 * Only returns CIP_SAFETY_CHECK_OK (with *mode_out/data_out filled in) if
 * BOTH agree the data is intact. */
cip_safety_check_result_t cip_safety_decode_pdu(const uint8_t *pdu, size_t pdu_len, size_t data_len,
                                                 uint8_t *mode_out, uint8_t *data_out);

/* Called by the UDP I/O loop after successfully validating an incoming
 * safety PDU from the scanner - applies the received command bytes. */
void cip_safety_write_output(const uint8_t *data, size_t len);

/* Called by the UDP I/O loop to get the current bytes + mode to send back
 * to the scanner as our safety status. */
size_t cip_safety_read_input(uint8_t *out, size_t out_cap);
uint8_t cip_safety_current_mode(void);

/* Called by the UDP I/O loop whenever validation fails, forces the safety
 * output to all-zero (safe state) and latches a fault that stays set until
 * acknowledged via the Safety Supervisor's Reset service. The three
 * "note_*_fault" functions record which diagnostic caught the problem
 * (their own counters, exposed via the Safety Validator object) but all
 * trip the same overall latch. */
void cip_safety_note_validation_fault(void);   /* Channel A (CRC/complement) failed */
void cip_safety_note_channel_mismatch_fault(void); /* Channel A/B disagreed          */
void cip_safety_note_timeout_fault(void);      /* no valid data within the timeout  */
void cip_safety_note_self_test_fault(void);    /* self-test found broken diagnostics */
bool cip_safety_is_faulted(void);

/* Runs a self-test: feeds known-good and known-bad vectors through both
 * channels and confirms each behaves as expected (accepts good data,
 * rejects corrupted data). This is what a real safety device's periodic
 * "proof test" is standing in for here - it exists to catch the case where
 * the checking logic ITSELF has silently broken, not just to check the
 * data. Call once at startup and periodically thereafter (see main.c). */
void cip_safety_self_test(void);

#endif /* ENIP_CIP_SAFETY_H */
