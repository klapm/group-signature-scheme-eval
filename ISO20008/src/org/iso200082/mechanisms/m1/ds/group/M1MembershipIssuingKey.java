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
 * Container class for the group membership issuing key.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1PrivateProperties
 * @see M1Parameters
 * @see M1Properties
 * @see M1PublicKey
 */
public class M1MembershipIssuingKey
{
  /** p' named as in the draft standard */
  private BigInteger p_prime = null;
  
  /** q' named as in the draft standard */
  private BigInteger q_prime = null;
  
  /**
   * Ctor, initializes p', q'
   * 
   * @param p_prime The prime p'
   * @param q_prime The prime q'
   */
  public M1MembershipIssuingKey(BigInteger p_prime, BigInteger q_prime)
  {
    this.p_prime = p_prime;
    this.q_prime = q_prime;
  }

  /**
   * Getter for p'
   * 
   * @return p'
   */
  public BigInteger getPPrime()
  {
    return this.p_prime;
  }

  /**
   * Getter for q'
   * 
   * @return q'
   */
  public BigInteger getQPrime()
  {
    return this.q_prime;
  }

}
