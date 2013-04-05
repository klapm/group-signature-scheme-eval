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

package org.iso200082.mechanisms.m1.ds.messages;

import java.math.BigInteger;

import org.iso200082.common.api.parties.Issuer;
import org.iso200082.mechanisms.m1.parties.M1Issuer;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;

/**
 * Represents the membership credential that gets issued by, well, the issuer
 * after a joiner successfully completes the protocol.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1Protocol
 * @see M1Issuer
 * @see Issuer
 */
public class M1MembershipCredential
{
  /** A named as in the draft standard */
  private BigInteger A  = null;
  
  /** e named as in the draft standard */
  private BigInteger e  = null;
  
  /**
   * Ctor, initializes the structure.
   * 
   * @param A named as in the draft standard
   * @param e named as in the draft standard
   */
  public M1MembershipCredential(BigInteger A, BigInteger e)
  {
    this.A = A;
    this.e = e;
  }

  /**
   * Getter for A
   * (do not confuse this with the lower-case 'a' from the public key!)
   * 
   * @return A
   */
  public BigInteger getA()
  {
    return this.A;
  }

  /**
   * Getter for e
   * 
   * @return e
   */
  public BigInteger getE()
  {
    return this.e;
  }
}
