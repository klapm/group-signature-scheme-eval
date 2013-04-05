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
import org.iso200082.mechanisms.m1.ds.proofs.M1U;
import org.iso200082.mechanisms.m1.parties.M1Issuer;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;


/**
 * Represents the join request that is initially sent by a joiner who wants
 * to become a member of the group.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1Protocol
 * @see M1Issuer
 * @see Issuer
 */
public class M1JoinRequest
{
  /** C_1 named as in the draft standard */
  private BigInteger   C_1 = null;
  
  /** The proof U named as in the draft standard */
  private M1U              U = null;
  
  /** Some sort of member id to get a linking base from and have some
   *  identifier for sessions */
  private String member_id = null;

  /**
   * Ctor, initializes values.
   * 
   * @param member_id A member ID identifying this particular user
   * @param C_1 named as in the draft standard
   * @param U named as in the draft standard
   */
  public M1JoinRequest(String member_id, BigInteger C_1, M1U U)
  {
    this.C_1 = C_1;
    this.U   = U;
    this.member_id = member_id;
  }

  /**
   * Getter for C_1
   * 
   * @return C_1
   */
  public BigInteger getC1()
  {
    return this.C_1;
  }

  /**
   * Getter for U
   * 
   * @return U
   */
  public M1U getU()
  {
    return this.U;
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
