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

import org.iso200082.common.api.revocation.NonRevocationProof;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m4.parties.M4Signer;
import org.iso200082.mechanisms.m4.parties.M4Verifier;

/**
 * The response for the challenge sent by the verifier to ensure a
 * {@link M4Signer} is not revoked. Used in conjunction with signature
 * revocation.
 * 
 * @see M4Verifier
 * @see M4Signer
 * @see M4NonRevokedChallenge
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 */
public class M4NonRevokedProof
<
  P
>
implements NonRevocationProof
{
  /** T, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> T;
  
  /** c, named as in the draft standard */
  private FqElement<P> c;
  
  /** su, named as in the draft standard */
  private FqElement<P> su;
  
  /** sv, named as in the draft standard */
  private FqElement<P> sv;
  
  /**
   * Ctor, bundles T, c, su, sv
   * @param T  Named as in the draft standard
   * @param c  Named as in the draft standard
   * @param su Named as in the draft standard
   * @param sv Named as in the draft standard
   */
  public M4NonRevokedProof(Point<FqElement<P>, Fq<P>> T, FqElement<P> c,
                                                         FqElement<P> su,
                                                         FqElement<P> sv)
  {
    this.T  = T;
    this.c  = c;
    this.su = su;
    this.sv = sv;
  }
  
  /**
   * Getter for T
   * @return T
   */
  public Point<FqElement<P>, Fq<P>> getT()
  {
    return this.T;
  }

  /**
   * Getter for c
   * @return c 
   */
  public FqElement<P> getC()
  {
    return this.c;
  }

  /**
   * Getter for su
   * @return su
   */
  public FqElement<P> getSu()
  {
    return this.su;
  }

  /**
   * Getter for sv
   * @return sv
   */
  public FqElement<P> getSv()
  {
    return this.sv;
  }

}
