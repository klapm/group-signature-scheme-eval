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

import org.iso200082.mechanisms.m5.parties.M5Opener;


/**
 * Bundles {@link M5OpenerPublicKey} and {@link M5MembershipOpeningKey}.
 * 
 * @see M5Opener
 * @see M5OpenerPublicKey
 * @see M5MembershipOpeningKey
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5OpenerProperties
<
  P
>
{
  /** The opener public key */
  private M5OpenerPublicKey<P> opk;
  
  /** The membership opening key */
  private M5MembershipOpeningKey<P> gmok;

  /**
   * Ctor, sets the opener public key and the membership opening key
   * 
   * @param opk  The opener public key
   * @param gmok The membership opening key
   */
  public M5OpenerProperties(M5OpenerPublicKey<P> opk, 
                            M5MembershipOpeningKey<P> gmok)
  {
    this.opk  = opk;
    this.gmok = gmok;
  }

  /**
   * Getter for the opener public key
   * @return The opener public key
   */
  public M5OpenerPublicKey<P> getOpenerPublicKey()
  {
    return this.opk;
  }

  /**
   * Getter for the membership opening key
   * @return The membership opening key
   */
  public M5MembershipOpeningKey<P> getMembershipOpeningKey()
  {
    return this.gmok;
  }
}
