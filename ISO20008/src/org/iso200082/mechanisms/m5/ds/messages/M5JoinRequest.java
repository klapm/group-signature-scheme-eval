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

package org.iso200082.mechanisms.m5.ds.messages;


import java.math.BigInteger;

import org.iso200082.mechanisms.m5.parties.M5Issuer;
import org.iso200082.mechanisms.m5.parties.M5Signer;


/**
 * Represents a join request that is initially sent by an aspirant to indicate
 * the intent to join a group.
 * 
 * @see M5JoinChallenge
 * @see M5JoinResponse
 * @see M5Issuer
 * @see M5Signer
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5JoinRequest
{
  /** C, named as in the standard */
  private BigInteger C;
  
  /**
   * Ctor, bundles C and the proof
   * @param C Named as in the standard
   */
  public M5JoinRequest(BigInteger C)
  {
    this.C = C;
  }

  /**
   * Getter for C
   * @return C
   */
  public BigInteger getC()
  {
    return this.C;
  }

}
