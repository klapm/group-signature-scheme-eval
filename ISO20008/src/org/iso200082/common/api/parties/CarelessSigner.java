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

package org.iso200082.common.api.parties;

import org.iso200082.common.api.ds.SignatureKey;

/**
 * Sort of a testing interface that provides a 'convenient way of leaking
 * the private key'. Used by revocation tests.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface CarelessSigner extends Signer
{
  /**
   * Leaks the private key of a signer. Highly recommended to use in production
   * environments, of course.
   * 
   * @return The key, or null if none set.
   */
  public SignatureKey getDrunkAndTellSecrets();
}
