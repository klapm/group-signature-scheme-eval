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
 * Represents the proof U (named as in the draft standard)
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1Protocol
 * @see M1Issuer
 * @see Issuer
 */
public class M1U
{
  /** c_hat named as in the draft standard */
  private BigInteger c_hat   = null;
  
  /** s_1-hat named as in the draft standard */
  private BigInteger s_1_hat = null;
  
  /** s_2-hat named as in the draft standard */
  private BigInteger s_2_hat = null;
    
  /**
   * Ctor, initializes the structure. 
   * 
   * @param c   c_hat named as in the draft standard
   * @param s_1 s_1_hat named as in the draft standard
   * @param s_2 s_2_hat named as in the draft standard
   */
  public M1U(BigInteger c, BigInteger s_1, BigInteger s_2)
  {
    c_hat   = c;
    s_1_hat = s_1;
    s_2_hat = s_2;
  }

  /**
   * Getter for C-hat
   * 
   * @return C-hat
   */
  public BigInteger getC()
  {
    return this.c_hat;
  }

  /**
   * Getter for s_1-hat
   * 
   * @return s_1-hat
   */
  public BigInteger getS1()
  {
    return this.s_1_hat;
  }

  /**
   * Getter for s_2-hat
   * 
   * @return s_2-hat
   */
  public BigInteger getS2()
  {
    return this.s_2_hat;
  }

}
