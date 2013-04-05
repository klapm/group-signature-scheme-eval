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

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.mechanisms.m1.ds.group.M1Parameters;
import org.iso200082.mechanisms.m1.ds.group.M1PublicKey;
import org.iso200082.mechanisms.m1.parties.M1Signer;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;


/**
 * Represents an anonymous signature as created by 
 * {@link M1Protocol#signMessage(BigInteger, String, M1PublicKey,
 * M1SignatureKey, M1Parameters, M1PrecomputationResult)}
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1Protocol
 * @see M1Signer
 * @see Signer
 */
public class M1Signature implements Signature
{
  /** c named as in the draft standard */
  private BigInteger   c  = null;

  /** s_1 named as in the draft standard */
  private BigInteger s_1  = null;

  /** s_2 named as in the draft standard */
  private BigInteger s_2  = null;

  /** s_3 named as in the draft standard */
  private BigInteger s_3  = null;

  /** s_4 named as in the draft standard */
  private BigInteger s_4  = null;

  /** s_5 named as in the draft standard */
  private BigInteger s_5  = null;

  /** s_9 named as in the draft standard */
  private BigInteger s_9  = null;

  /** s_10 named as in the draft standard */
  private BigInteger s_10 = null;

  /** T_1 named as in the draft standard */
  private BigInteger T_1  = null;

  /** T_2 named as in the draft standard */
  private BigInteger T_2  = null;

  /** T_3 named as in the draft standard */
  private BigInteger T_3  = null;

  /** T_4 named as in the draft standard */
  private BigInteger T_4  = null;
  
  /**
   * Ctor, initializes the structure.
   * 
   * @param c    named as in the draft standard
   * @param s_1  named as in the draft standard
   * @param s_2  named as in the draft standard
   * @param s_3  named as in the draft standard
   * @param s_4  named as in the draft standard
   * @param s_5  named as in the draft standard
   * @param s_9  named as in the draft standard
   * @param s_10 named as in the draft standard
   * @param T_1  named as in the draft standard
   * @param T_2  named as in the draft standard
   * @param T_3  named as in the draft standard
   * @param T_4  named as in the draft standard
   */
  public M1Signature(BigInteger c,
                            BigInteger s_1, BigInteger s_2, BigInteger s_3,
                            BigInteger s_4, BigInteger s_5, BigInteger s_9,
                            BigInteger s_10,
                            BigInteger T_1, BigInteger T_2, BigInteger T_3,
                            BigInteger T_4)
  {
    this.c    = c;
    this.s_1  = s_1;
    this.s_2  = s_2;
    this.s_3  = s_3;
    this.s_4  = s_4;
    this.s_5  = s_5;
    this.s_9  = s_9;
    this.s_10 = s_10;
    this.T_1  = T_1;
    this.T_2  = T_2;
    this.T_3  = T_3;
    this.T_4  = T_4;
  }
  
  /**
   * Ctor, initializes the structure. The array is expected to be as returned
   * by {@link M1Protocol#signMessage(BigInteger, String, M1PublicKey,
   * M1SignatureKey, M1Parameters, M1PrecomputationResult)}.
   * 
   * @param data c, s_1, s_2, s_3, s_4, s_5, s_9, s_10, T_1, T_2, T_3, T_4
   */
  public M1Signature(BigInteger[] data)
  {
    this.c    = data[0];
    this.s_1  = data[1];
    this.s_2  = data[2];
    this.s_3  = data[3];
    this.s_4  = data[4];
    this.s_5  = data[5];
    this.s_9  = data[6];
    this.s_10 = data[7];
    this.T_1  = data[8];
    this.T_2  = data[9];
    this.T_3  = data[10];
    this.T_4  = data[11];
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

  /**
   * Getter for s_4
   * 
   * @return s_4
   */
  public BigInteger getS4()
  {
    return this.s_4;
  }

  /**
   * Getter for s_5
   * 
   * @return s_5
   */
  public BigInteger getS5()
  {
    return this.s_5;
  }

  /**
   * Getter for s_9
   * 
   * @return s_9
   */
  public BigInteger getS9()
  {
    return this.s_9;
  }

  /**
   * Getter for s_10
   * 
   * @return s_10
   */
  public BigInteger getS10()
  {
    return this.s_10;
  }

  /**
   * Getter for T_1
   * 
   * @return T_1
   */
  public BigInteger getT1()
  {
    return this.T_1;
  }

  /**
   * Getter for T_2
   * 
   * @return T_2
   */
  public BigInteger getT2()
  {
    return this.T_2;
  }

  /**
   * Getter for T_3
   * 
   * @return T_3
   */
  public BigInteger getT3()
  {
    return this.T_3;
  }

  /**
   * Getter for T_4
   * 
   * @return T_4
   */
  public BigInteger getT4()
  {
    return this.T_4;
  }

  /**
   * Alias for {@link #getT4()}
   * 
   * @return T_1
   */
  public BigInteger getRevocationInformation()
  {
    return getT4();
  }

}
