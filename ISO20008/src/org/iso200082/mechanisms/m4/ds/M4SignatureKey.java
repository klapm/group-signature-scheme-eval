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

package org.iso200082.mechanisms.m4.ds;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m4.parties.M4Signer;

/**
 * Represents a signature key for mechanism 4.
 * 
 * @see M4Signer
 * @see Signature
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4SignatureKey
<
  P
>
implements SignatureKey

{
  /** A, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> A;

  /** B, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> B;

  /** C, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> C;

  /** D, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> D;

  /** f, named as in the draft standard */
  private FqElement<P>               f;
  
  /**
   * Ctor, bundles A, B, C, D, f
   * 
   * @param A Named as in the draft standard
   * @param B Named as in the draft standard
   * @param C Named as in the draft standard
   * @param D Named as in the draft standard
   * @param f Named as in the draft standard
   */
  public M4SignatureKey(Point<FqElement<P>, Fq<P>> A,
                        Point<FqElement<P>, Fq<P>> B,
                        Point<FqElement<P>, Fq<P>> C,
                        Point<FqElement<P>, Fq<P>> D,
                        FqElement<P> f)
  {
    this.A = A;
    this.B = B;
    this.C = C;
    this.D = D;
    this.f = f;
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

  /**
   * Getter for D
   * @return D
   */
  public Point<FqElement<P>, Fq<P>> getD()
  {
    return this.D;
  }

  /**
   * Getter for f
   * @return f
   */
  public FqElement<P> getF()
  {
    return this.f;
  }

}
