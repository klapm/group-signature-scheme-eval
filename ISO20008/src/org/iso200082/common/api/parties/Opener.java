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

import org.iso200082.common.api.ds.Signature;

/**
 * Opening authority. It is able to 'open' an otherwise anonymous (group)
 * signature and thus tell who created it. 
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface Opener
{
  /**
   * Opens a given signature and returns the signer's identity.
   * 
   * @param signature The signature to open
   * 
   * @return The signers identity string
   */
  public String openSignature(Signature signature);
}
