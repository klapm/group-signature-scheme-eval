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

package org.iso200082.mechanisms.m4.ds.messages;

import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m4.parties.M4Issuer;
import org.iso200082.mechanisms.m4.parties.M4Signer;

/**
 * Represents a membership credential, to be received when completing a
 * join.
 * 
 * @see M4Issuer
 * @see M4Signer
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4MembershipCredential
<
  P
>
{
  /** A, named as in the draft standard */
  Point<FqElement<P>, Fq<P>> A;

  /** B, named as in the draft standard */
  Point<FqElement<P>, Fq<P>> B;

  /** C, named as in the draft standard */
  Point<FqElement<P>, Fq<P>> C;
  
  /**
   * Ctor, bundles A, B and C
   * 
   * @param A Named as in the draft standard
   * @param B Named as in the draft standard
   * @param C Named as in the draft standard
   */
  public M4MembershipCredential(Point<FqElement<P>, Fq<P>> A,
                                Point<FqElement<P>, Fq<P>> B,
                                Point<FqElement<P>, Fq<P>> C)
  {
    this.A = A;
    this.B = B;
    this.C = C;
  }

  /**
   * Getter for A
   * @return A
   */
  public Point<FqElement<P>, Fq<P>> getA()
  {
    return this.A;
  }

  /**
   * Getter for B
   * @return B
   */
  public Point<FqElement<P>, Fq<P>> getB()
  {
    return this.B;
  }

  /**
   * Getter for C
   * @return C
   */
  public Point<FqElement<P>, Fq<P>> getC()
  {
    return this.C;
  }

}
