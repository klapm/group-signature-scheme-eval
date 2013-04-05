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

/**
 * A join request, issued by an aspirant to indicate a join intention.
 * The join process is encapsulated in {@link M4Issuer#addMember(String)},
 * though.
 * 
 * @see M4Issuer
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4JoinRequest
<
  P
>
{
  /** Q2 as in the draft standard */
  private Point<FqElement<P>, Fq<P>> Q2;
  
  /** v as in the draft standard */
  private FqElement<P> v;
  
  /** w as in the draft standard */
  private FqElement<P> w;
  
  /**
   * Ctor, bundles Q2, v, w.
   * 
   * @param Q2 Named as in the draft standard
   * @param v  Named as in the draft standard
   * @param w  Named as in the draft standard
   */
  public M4JoinRequest(Point<FqElement<P>, Fq<P>> Q2, FqElement<P> v, FqElement<P> w)
  {
    this.Q2 = Q2;
    this.v  = v;
    this.w  = w;
  }

  /**
   * Getter for Q2
   * @return Q2
   */
  public Point<FqElement<P>, Fq<P>> getQ2()
  {
    return this.Q2;
  }

  /**
   * Getter for v
   * @return v
   */
  public FqElement<P> getV()
  {
    return this.v;
  }

  /**
   * Getter for w
   * @return w
   */
  public FqElement<P> getW()
  {
    return this.w;
  }

}
