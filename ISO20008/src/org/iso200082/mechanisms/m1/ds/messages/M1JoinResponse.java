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
import org.iso200082.mechanisms.m1.ds.proofs.M1V;
import org.iso200082.mechanisms.m1.ds.proofs.M1W;
import org.iso200082.mechanisms.m1.parties.M1Issuer;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;


/**
 * Represents the join response that is the answer from the joiner to the
 * challenge sent by the issuer beforehand.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1Protocol
 * @see M1JoinChallenge
 * @see M1Issuer
 * @see Issuer
 */
public class M1JoinResponse
{

  /** C_2 named as in the draft standard */
  private BigInteger C_2       = null;

  /** V named as in the draft standard */
  private M1V          V         = null;

  /** W named as in the draft standard */
  private M1W          W         = null;
  
  /** Some sort of member id to get a linking base from and have some
   *  identifier for sessions */
  private String     member_id = null;
  
  /**
   * Ctor, initializes the structure.
   * 
   * @param member_id A member ID identifying this particular user
   * @param C_2       named as in the draft standard
   * @param V         named as in the draft standard
   * @param W         named as in the draft standard
   */
  public M1JoinResponse(String member_id, BigInteger C_2, M1V V, M1W W)
  {
    this.C_2       = C_2;
    this.V         = V;
    this.W         = W;
    this.member_id = member_id;
  }

  /**
   * Getter for C_2
   * 
   * @return C_2
   */
  public BigInteger getC2()
  {
    return this.C_2;
  }

  /**
   * Getter for V
   * 
   * @return V
   */
  public M1V getV()
  {
    return this.V;
  }

  /**
   * Getter for W
   * 
   * @return W
   */
  public M1W getW()
  {
    return this.W;
  }

  /**
   * Getter for the member ID
   * 
   * @return The member ID
   */
  public String getMemberIdentifier()
  {
    return member_id;
  }
}
