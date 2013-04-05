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
 * Represents a join response which is sent as, well, a response to the
 * challenge sent by the issuer
 * 
 * @see M5JoinChallenge
 * @see M5JoinRequest
 * @see M5Issuer
 * @see M5Signer
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5JoinResponse
<
  P
>
{
  /** xi, named as in the standard */
  private BigInteger xi;

  /** Ai', named as in the standard */
  private BigInteger Ai_prime;

  /** hi, named as in the standard */
  private Point<FqElement<P>, Fq<P>> hi;
  
  /**
   * Ctor, bundles xi, Ai', hi
   * @param xi Named as in the standard
   * @param Ai_prime Named as in the standard
   * @param hi Named as in the standard
   */
  public M5JoinResponse(BigInteger xi, BigInteger Ai_prime,
                        Point<FqElement<P>, Fq<P>> hi)
  {
    this.xi       = xi;
    this.Ai_prime = Ai_prime;
    this.hi       = hi;
  }

  /**
   * Getter for xi
   * @return xi
   */
  public BigInteger getXi()
  {
    return this.xi;
  }

  /**
   * Getter for Ai'
   * @return Ai'
   */
  public BigInteger getAiPrime()
  {
    return this.Ai_prime;
  }

  /**
   * Getter for hi
   * @return hi
   */
  public Point<FqElement<P>, Fq<P>> getHi()
  {
    return this.hi;
  }
}
