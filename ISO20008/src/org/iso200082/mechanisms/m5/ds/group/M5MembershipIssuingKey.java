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

import java.math.BigInteger;

import org.iso200082.mechanisms.m5.parties.M5Issuer;

/**
 * Represents the group's membership issuing key
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see M5Issuer
 */
public class M5MembershipIssuingKey
{
  /** p1, named as in the standard */
  private BigInteger p1;
  
  /** p1, named as in the standard */
  private BigInteger p2;
  
  /**
   * Ctor, sets p1, p2.
   * 
   * @param p1 The prime p1, named as in the standard
   * @param p2 The prime p2, named as in the standard
   */
  public M5MembershipIssuingKey(BigInteger p1, BigInteger p2)
  {
    this.p1 = p1;
    this.p2 = p2;
  }

  /**
   * Getter for p1
   * @return p1
   */
  public BigInteger getP1()
  {
    return this.p1;
  }

  /**
   * Getter for p2
   * @return p2
   */
  public BigInteger getP2()
  {
    return this.p2;
  }

}
