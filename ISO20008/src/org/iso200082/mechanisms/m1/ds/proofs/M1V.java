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

package org.iso200082.mechanisms.m1.ds.proofs;

import java.math.BigInteger;

import org.iso200082.common.api.parties.Issuer;
import org.iso200082.mechanisms.m1.parties.M1Issuer;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;

/**
 * Represents the proof V (named as in the draft standard)
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1Protocol
 * @see M1Issuer
 * @see Issuer
 */
public class M1V
{

  /** c' named as in the draft standard */
  BigInteger c_prime = null;
  
  /** s' named as in the draft standard */
  BigInteger s_prime = null;
    
  /**
   * Ctor, initializes the structure.
   * 
   * @param c_prime c'
   * @param s_prime s'
   */
  public M1V(BigInteger c_prime, BigInteger s_prime)
  {
    this.c_prime = c_prime;
    this.s_prime = s_prime;
  }

  /**
   * Getter for c'
   * 
   * @return c'
   */
  public BigInteger getCPrime()
  {
    return this.c_prime;
  }

  /**
   * Getter for s'
   * 
   * @return s'
   */
  public BigInteger getSPrime()
  {
    return this.s_prime;
  }
}
