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

import org.iso200082.common.api.revocation.NonRevocationChallenge;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m4.parties.M4Signer;
import org.iso200082.mechanisms.m4.parties.M4Verifier;

/**
 * A challenge that is sent by the verifier to ensure a particular signer
 * is not revoked. Used in conjunction with signature revocation, see
 * 6.4.6 in the draft standard.
 * 
 * @see M4Verifier
 * @see M4Signer
 * @see M4NonRevokedProof
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4NonRevokedChallenge
<
  P
>
implements NonRevocationChallenge
{
  /** J, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> J;

  /** K, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> K;
  
  /**
   * Ctor, bundles J and K
   * @param J Named as in the draft standard
   * @param K Named as in the draft standard
   */
  public M4NonRevokedChallenge(Point<FqElement<P>, Fq<P>> J,
                               Point<FqElement<P>, Fq<P>> K)
  {
    this.J = J;
    this.K = K;
  }

  /**
   * Getter for J
   * @return J
   */
  public Point<FqElement<P>, Fq<P>> getJ()
  {
    return this.J;
  }

  /**
   * Getter for K
   * @return K
   */
  public Point<FqElement<P>, Fq<P>> getK()
  {
    return this.K;
  }

}
