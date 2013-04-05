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

import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m5.parties.M5Issuer;
import org.iso200082.mechanisms.m5.parties.M5Signer;


/**
 * Represents a membership credential, which is created upon successful
 * completion of the join phase and then used as part of the signature key.
 * 
 * @see M5JoinChallenge
 * @see M5JoinRequest
 * @see M5JoinResponse
 * @see M5Issuer
 * @see M5Signer
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5MembershipCredential
<
  P
>
{
  /** Ai, named as in the standard */
  private BigInteger Ai;
  
  /** ei', named as in the standard */
  private BigInteger ei_prime;

  /** Bi, named as in the standard */
  private BigInteger Bi;

  /** hi, named as in the standard */
  private Point<FqElement<P>, Fq<P>> hi;

  /**
   * Ctor, bundles Ai, ei', Bi, hi
   * 
   * @param Ai Named as in the standard
   * @param ei_prime Named as in the standard
   * @param Bi Named as in the standard
   * @param hi Named as in the standard
   */
  public M5MembershipCredential(BigInteger Ai, BigInteger ei_prime,
                                BigInteger Bi, Point<FqElement<P>, Fq<P>> hi)
  {
    this.Ai       = Ai;
    this.ei_prime = ei_prime;
    this.Bi       = Bi;
    this.hi       = hi;
  }

  /**
   * Getter for hi
   * @return hi
   */
  public Point<FqElement<P>, Fq<P>> getHi()
  {
    return this.hi;
  }

  /**
   * Getter for Ai
   * @return Ai
   */
  public BigInteger getAi()
  {
    return this.Ai;
  }

  /**
   * Getter for ei'
   * @return ei'
   */
  public BigInteger getEiPrime()
  {
    return this.ei_prime;
  }

  /**
   * Getter for Bi
   * @return Bi
   */
  public BigInteger getBi()
  {
    return this.Bi;
  }

}
