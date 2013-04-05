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
 * Represents the proof W (named as in the draft standard)
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1Protocol
 * @see M1Issuer
 * @see Issuer
 */
public class M1W
{
  /** c named as in the draft standard */
  private BigInteger c   = null;
  
  /** s_1 named as in the draft standard */
  private BigInteger s_1 = null;
  
  /** s_2 named as in the draft standard */
  private BigInteger s_2 = null;
  
  /** s_3 named as in the draft standard */
  private BigInteger s_3 = null;
  
  /**
   * Ctor, initializes the structure.
   * 
   * @param c   named as in the draft standard
   * @param s_1 named as in the draft standard
   * @param s_2 named as in the draft standard
   * @param s_3 named as in the draft standard
   */
  public M1W(BigInteger c, BigInteger s_1, BigInteger s_2, BigInteger s_3)
  {
    this.c   = c;
    this.s_1 = s_1;
    this.s_2 = s_2;
    this.s_3 = s_3;
  }

  /**
   * Getter for c
   * 
   * @return c
   */
  public BigInteger getC()
  {
    return this.c;
  }

  /**
   * Getter for s_1
   * 
   * @return s_1
   */
  public BigInteger getS1()
  {
    return this.s_1;
  }

  /**
   * Getter for s_2
   * 
   * @return s_2
   */
  public BigInteger getS2()
  {
    return this.s_2;
  }

  /**
   * Getter for s_3
   * 
   * @return s_3
   */
  public BigInteger getS3()
  {
    return this.s_3;
  }

}
