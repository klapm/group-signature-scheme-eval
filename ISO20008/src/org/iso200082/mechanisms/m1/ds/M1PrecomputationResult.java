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

package org.iso200082.mechanisms.m1.ds;

import java.math.BigInteger;

import org.iso200082.mechanisms.m1.parties.M1Issuer;
import org.iso200082.mechanisms.m1.parties.M1Signer;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;

/**
 * Precomputation result to hold intermediate signature values if enabled.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see M1Issuer
 * @see M1Signer
 * @see M1Protocol
 */
public class M1PrecomputationResult
{
  /** T1, named as in the draft standard */
  private BigInteger T1;
  
  /** T2, named as in the draft standard */
  private BigInteger T2;
  
  /** T3, named as in the draft standard */
  private BigInteger T3;
  
  /** T4, named as in the draft standard */
  private BigInteger T4;
  
  /** r1, named as in the draft standard */
  private BigInteger r1;
  
  /** r2, named as in the draft standard */
  private BigInteger r2;
  
  /** r3, named as in the draft standard */
  private BigInteger r3;
  
  /** r4, named as in the draft standard */
  private BigInteger r4;
  
  /** r5, named as in the draft standard */
  private BigInteger r5;
  
  /** r9, named as in the draft standard */
  private BigInteger r9;
  
  /** r10, named as in the draft standard */
  private BigInteger r10;
  
  /** d1, named as in the draft standard */
  private BigInteger d1;
  
  /** d2, named as in the draft standard */
  private BigInteger d2;
  
  /** d3, named as in the draft standard */
  private BigInteger d3;
  
  /** d4, named as in the draft standard */
  private BigInteger d4;
  
  /** d5, named as in the draft standard */
  private BigInteger d5;
  
  /** w1, named as in the draft standard */
  private BigInteger w1;
  
  /** w2, named as in the draft standard */
  private BigInteger w2;
  
  /** w3, named as in the draft standard */
  private BigInteger w3;

  /**
   * Ctor, initializes the structure.
   * 
   * @param T1  Named as in the draft
   * @param T2  Named as in the draft
   * @param T3  Named as in the draft
   * @param r1  Named as in the draft
   * @param r2  Named as in the draft
   * @param r3  Named as in the draft
   * @param r4  Named as in the draft
   * @param r5  Named as in the draft
   * @param r9  Named as in the draft
   * @param r10 Named as in the draft
   * @param d1  Named as in the draft
   * @param d2  Named as in the draft
   * @param d3  Named as in the draft
   * @param d4  Named as in the draft
   * @param w1  Named as in the draft
   * @param w2  Named as in the draft
   * @param w3  Named as in the draft
   */
  public M1PrecomputationResult(BigInteger T1,  BigInteger T2,  BigInteger T3,
                                BigInteger r1,  BigInteger r2,  BigInteger r3,
                                BigInteger r4,  BigInteger r5,  BigInteger r9,
                                BigInteger r10, BigInteger d1,  BigInteger d2, 
                                BigInteger d3,  BigInteger d4,  BigInteger w1,
                                BigInteger w2,  BigInteger w3 )
  {
    this.T1  = T1;
    this.T2  = T2;
    this.T3  = T3;
    this.r1  = r1;
    this.r2  = r2;
    this.r3  = r3;
    this.r4  = r4;
    this.r5  = r5;
    this.r9  = r9;
    this.r10 = r10;
    this.d1  = d1;
    this.d2  = d2;
    this.d3  = d3;
    this.d4  = d4;  
    this.w1  = w1;
    this.w2  = w2;
    this.w3  = w3;   
  }

  /**
   * Getter for T1
   * @return T1
   */
  public BigInteger getT1()
  {
    return this.T1;
  }

  /**
   * Getter for T2
   * @return T2
   */
  public BigInteger getT2()
  {
    return this.T2;
  }

  /**
   * Getter for T3
   * @return T3
   */
  public BigInteger getT3()
  {
    return this.T3;
  }

  /**
   * Getter for T4
   * @return T4
   */
  public BigInteger getT4()
  {
    return this.T4;
  }

  /**
   * Getter for r1
   * @return r1
   */
  public BigInteger getR1()
  {
    return this.r1;
  }

  /**
   * Getter for r2
   * @return r2
   */
  public BigInteger getR2()
  {
    return this.r2;
  }

  /**
   * Getter for r3
   * @return r3
   */
  public BigInteger getR3()
  {
    return this.r3;
  }

  /**
   * Getter for r4
   * @return r4
   */
  public BigInteger getR4()
  {
    return this.r4;
  }

  /**
   * Getter for r5
   * @return r5
   */
  public BigInteger getR5()
  {
    return this.r5;
  }

  /**
   * Getter for r9
   * @return r9
   */
  public BigInteger getR9()
  {
    return this.r9;
  }

  /**
   * Getter for r10
   * @return r10
   */
  public BigInteger getR10()
  {
    return this.r10;
  }

  /**
   * Getter for d1
   * @return d1
   */
  public BigInteger getD1()
  {
    return this.d1;
  }

  /**
   * Getter for d2
   * @return d2
   */
  public BigInteger getD2()
  {
    return this.d2;
  }

  /**
   * Getter for d3
   * @return d3
   */
  public BigInteger getD3()
  {
    return this.d3;
  }

  /**
   * Getter for d4
   * @return d4
   */
  public BigInteger getD4()
  {
    return this.d4;
  }

  /**
   * Getter for d5
   * @return d5
   */
  public BigInteger getD5()
  {
    return this.d5;
  }

  /**
   * Getter for w1
   * @return w1
   */
  public BigInteger getW1()
  {
    return this.w1;
  }

  /**
   * Getter for w2
   * @return w2
   */
  public BigInteger getW2()
  {
    return this.w2;
  }

  /**
   * Getter for w3
   * @return w3
   */
  public BigInteger getW3()
  {
    return this.w3;
  }

  /**
   * Setter for d5
   * @param d5 The value for d5
   */
  public void setD5(BigInteger d5)
  {
    this.d5 = d5;
  }
  
  /**
   * Setter for T4
   * @param t4 The value for T4
   */
  public void setT4(BigInteger t4)
  {
    this.T4 = t4;
  }
  
}
