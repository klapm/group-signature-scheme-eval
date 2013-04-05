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

package org.iso200082.mechanisms.m1.ds.group;

import java.math.BigInteger;

/**
 * Container class for the group's private properties.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0

 * @see M1Parameters
 * @see M1MembershipIssuingKey
 * @see M1Properties
 * @see M1PublicKey
 */
public class M1PrivateProperties
{
  /** The membership issuing key */
  private M1MembershipIssuingKey gmik = null;
  
  /** The prime p */
  private BigInteger p;
  
  /** The prime q */
  private BigInteger q;
 
  /**
   * Ctor, initializes values.
   * 
   * @param gmik The membership issuing key
   * @param p The prime p
   * @param q The prime q
   */
  public M1PrivateProperties(M1MembershipIssuingKey gmik,
                                BigInteger p, BigInteger q)
  {
    this.gmik = gmik;
    this.p    = p;
    this.q    = q;
  }

  /**
   * Getter for the group membership issuing key
   * 
   * @return The key
   */
  public M1MembershipIssuingKey getGroupMembershipIssuingKey()
  {
    return this.gmik;
  }

  /**
   * Getter for the prime p
   * 
   * @return p
   */
  public BigInteger getP()
  {
    return this.p;
  }

  /**
   * Getter for the prime q
   * 
   * @return q
   */
  public BigInteger getQ()
  {
    return this.q;
  }
  
  /**
   * Getter for p' from the membership issuing key
   * 
   * @return p'
   */
  public BigInteger getPPrime()
  {
    return gmik.getPPrime();
  }
  
  /**
   * Getter for q' from the membership issuing key
   * 
   * @return q'
   */
  public BigInteger getQPrime()
  {
    return gmik.getQPrime();
  }
}
