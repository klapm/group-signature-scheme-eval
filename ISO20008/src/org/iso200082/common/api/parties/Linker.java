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
 * Separate linking party, although typically everyone is able to tell from
 * two signatures whether the author was the same (depending on the mechanism). 
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface Linker
{
  /**
   * Tests whether two signatures were created by the same author
   * 
   * @param s1 Signature one
   * @param s2 Signature two
   * 
   * @return true if both signatures originate from the same author, false
   * otherwise
   */
  public boolean isSameAuthor(Signature s1, Signature s2);
}
