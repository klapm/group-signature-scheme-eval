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

package org.iso200082.mechanisms.m4.ds.group;

import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.mechanisms.m4.parties.M4Issuer;

/**
 * The group's membership issuing key, to be resided at the {@link M4Issuer}.
 * 
 * @see M4Issuer
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4MembershipIssuingKey
<
  P
>
{
  /** x as in the standard */
  private FqElement<P> x;
  
  /** y as in the standard */
  private FqElement<P> y;

  /**
   * Ctor, initializes x and y
   * @param x As in the standard
   * @param y As in the standard
   */
  public M4MembershipIssuingKey(FqElement<P> x, FqElement<P> y)
  {
    this.x = x;
    this.y = y;
  }

  /**
   * Getter for x
   * @return x
   */
  public FqElement<P> getX()
  {
    return this.x;
  }

  /**
   * Getter for y
   * @return y
   */
  public FqElement<P> getY()
  {
    return this.y;
  }
}
