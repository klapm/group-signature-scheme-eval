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

package org.iso200082.mechanisms.m5.ds;


import java.math.BigInteger;

import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m5.parties.M5Signer;
import org.iso200082.mechanisms.m5.parties.M5Verifier;


/**
 * Represents a mechanism five signature key
 * 
 * @see M5Signer
 * @see M5Verifier
 * @see M5Signature
 * 
 * @param <P> The primitive Type to use
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5SignatureKey<P> implements SignatureKey
{
  /** xi, named as in the standard */
  private BigInteger xi;

  /** Ai, named as in the standard */
  private BigInteger Ai;

  /** ei', named as in the standard */
  private BigInteger ei_prime;

  /** Bi, named as in the standard */
  private BigInteger Bi;

  /** hi, named as in the standard */
  private Point<FqElement<P>, Fq<P>> hi;

  /**
   * Ctor, bundles xi, Ai, ei', Bi, hi together to form a signature key
   * 
   * @param xi Named as in the standard
   * @param Ai Named as in the standard
   * @param ei_prime Named as in the standard
   * @param Bi Named as in the standard
   * @param hi Named as in the standard
   */
  public M5SignatureKey(BigInteger xi, BigInteger Ai, BigInteger ei_prime,
                        BigInteger Bi, Point<FqElement<P>, Fq<P>> hi)
  {
    this.xi       = xi;
    this.Ai       = Ai;
    this.ei_prime = ei_prime;
    this.Bi       = Bi;
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

  /**
   * Getter for hi
   * @return hi
   */
  public Point<FqElement<P>, Fq<P>> getHi()
  {
    return this.hi;
  }

}
