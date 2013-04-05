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

import org.iso200082.mechanisms.m5.M5Scheme;

/**
 * Represents the group's public key.
 * 
 * @see M5Scheme
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5PublicKey
{
  /** n, named as in the standard */
  private BigInteger n;

  /** a0, named as in the standard */
  private BigInteger a0;

  /** a1, named as in the standard */
  private BigInteger a1;

  /** a2, named as in the standard */
  private BigInteger a2;

  /** b, named as in the standard */
  private BigInteger b;

  /** w, named as in the standard */
  private BigInteger w;

  /**
   * Ctor, bundles n, a0, a1, a2, b, w
   * @param n  Named as in the standard
   * @param a0 Named as in the standard
   * @param a1 Named as in the standard
   * @param a2 Named as in the standard
   * @param b  Named as in the standard
   * @param w  Named as in the standard
   */
  public M5PublicKey(BigInteger n,  BigInteger a0, BigInteger a1,
                     BigInteger a2, BigInteger b,  BigInteger w)
  {
    this.n  = n;
    this.a0 = a0;
    this.a1 = a1;
    this.a2 = a2;
    this.b  = b;
    this.w  = w;
  }

  /**
   * Getter for n
   * @return n
   */
  public BigInteger getN()
  {
    return this.n;
  }

  /**
   * Getter for a0
   * @return a0
   */
  public BigInteger getA0()
  {
    return this.a0;
  }

  /**
   * Getter for a1
   * @return a1
   */
  public BigInteger getA1()
  {
    return this.a1;
  }

  /**
   * Getter for a2
   * @return a2
   */
  public BigInteger getA2()
  {
    return this.a2;
  }

  /**
   * Getter for b
   * @return b
   */
  public BigInteger getB()
  {
    return this.b;
  }

  /**
   * Getter for w
   * @return w
   */
  public BigInteger getW()
  {
    return this.w;
  }

}
