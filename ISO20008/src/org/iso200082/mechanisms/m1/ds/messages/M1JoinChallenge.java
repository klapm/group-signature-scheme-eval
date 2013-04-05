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
 * Represents the join challenge that is sent by the issuer after receiving
 * a join request.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1JoinRequest
 * @see M1Protocol
 * @see M1Issuer
 * @see Issuer
 */
public class M1JoinChallenge
{
  /** The issuer-chosen random alpha */
  BigInteger alpha = null;
  
  /** The issuer-chosen random beta */
  BigInteger beta  = null;
    
  /**
   * Ctor, initializes alpha and beta as given.
   * 
   * @param alpha The random alpha
   * @param beta  The random beta
   */
  public M1JoinChallenge(BigInteger alpha, BigInteger beta)
  {
    this.alpha = alpha;
    this.beta  = beta;
  }
  
  /**
   * Getter for alpha
   * 
   * @return alpha
   */
  public BigInteger getAlpha()
  {
    return this.alpha;
  }

  /**
   * Getter for beta
   * 
   * @return beta
   */
  public BigInteger getBeta()
  {
    return this.beta;
  }
}
