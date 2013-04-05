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
 * Container class for the group's public key.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see M1Parameters
 * @see M1MembershipIssuingKey
 * @see M1Properties
 * @see M1PrivateProperties
 */
public class M1PublicKey
{
  /** n named as in the draft standard */
  private BigInteger n   = null;
  
  /** a named as in the draft standard */
  private BigInteger a   = null;
  
  /** a0 named as in the draft standard */
  private BigInteger a_0 = null;
  
  /** g named as in the draft standard */
  private BigInteger g   = null;
  
  /** h named as in the draft standard */
  private BigInteger h   = null;
  
  /** b named as in the draft standard */
  private BigInteger b   = null;
  
  /**
   * Ctor, initializes values 
   * @param n   named as in the draft standard
   * @param a   named as in the draft standard
   * @param a_0 named as in the draft standard
   * @param g   named as in the draft standard
   * @param h   named as in the draft standard
   * @param b   named as in the draft standard
   */
  public M1PublicKey(BigInteger n, BigInteger a, BigInteger a_0,
                        BigInteger g, BigInteger h, BigInteger b)
  {
    this.n   = n;
    this.a   = a;
    this.a_0 = a_0;
    this.g   = g;
    this.h   = h;
    this.b   = b;
  }

  /**
   * Getter for the public modulus n
   * 
   * @return n
   */
  public BigInteger getN()
  {
    return this.n;
  }

  /**
   * Getter for a
   * 
   * @return a
   */
  public BigInteger getA()
  {
    return this.a;
  }

  /**
   * Getter for a0
   * 
   * @return a0
   */
  public BigInteger getA0()
  {
    return this.a_0;
  }

  /**
   * Getter for g
   * 
   * @return g
   */
  public BigInteger getG()
  {
    return this.g;
  }

  /**
   * Getter for h
   * 
   * @return h
   */
  public BigInteger getH()
  {
    return this.h;
  }

  /**
   * Getter for b
   * 
   * @return b
   */
  public BigInteger getB()
  {
    return this.b;
  }
  
}
