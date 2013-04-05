/*
 * This file is part of an unofficial ISO20008-2.2 sample implementation to
 * evaluate certain schemes for their applicability on Android-based mobile
 * devices. The source is licensed under the modified 3-clause BSD license,
 * see the readme.
 * 
 * The code was published in conjunction with the publication called 
 * "Group Signatures on Mobile Devices: Practical Experiences" by
 * Potzmader, Winter, Hein, Hanser, Teufl and Chen
 */

package org.iso200082.common.api.revocation;

import org.iso200082.common.api.parties.Verifier;


/**
 * Non-revocation challenge issued by the verifier on signature revocation
 * checks. No active actions here, just a means to exchange the challenge.
 * 
 * See section 6.4.6 of the draft standard for its purpose.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see Verifier
 * @see RevocationPolicy
 */
public interface NonRevocationChallenge
{
  // intentionally empty.
}
