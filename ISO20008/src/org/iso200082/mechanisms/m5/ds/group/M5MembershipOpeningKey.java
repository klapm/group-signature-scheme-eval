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

package org.iso200082.mechanisms.m5.ds.group;

import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.mechanisms.m5.parties.M5Opener;

/**
 * Represents the group's membership opening key. Used by the {@link M5Opener}
 * to open signatures.
 * 
 * @see M5Opener
 * @see M5OpenerPublicKey
 * @see M5OpenerProperties
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5MembershipOpeningKey
<
  P
>
{  
  /** y1, named as in the standard */
  private FqElement<P> y1;

  /** y2, named as in the standard */
  private FqElement<P> y2;

  /**
   * Ctor, sets y1 and y2.
   * 
   * @param y1 Named as in the standard
   * @param y2 Named as in the standard
   */
  public M5MembershipOpeningKey(FqElement<P> y1, FqElement<P> y2)
  {
    this.y1 = y1;
    this.y2 = y2;
  }

  /**
   * Getter for y1
   * @return y1
   */
  public FqElement<P> getY1()
  {
    return this.y1;
  }

  /**
   * Getter for y2
   * @return y2
   */
  public FqElement<P> getY2()
  {
    return this.y2;
  }

}
