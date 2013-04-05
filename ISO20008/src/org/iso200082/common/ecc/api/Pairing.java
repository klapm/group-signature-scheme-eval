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

package org.iso200082.common.ecc.api;

import java.util.Random;

import org.iso200082.common.ecc.elements.Fq12Element;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.CurveField;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.ecc.fields.towerextension.Fq12;
import org.iso200082.common.ecc.fields.towerextension.Fq2;

/**
 * Pairing Interface. Any pairing mappings are supposed to implement this
 * interface.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @param <P> The primitive Type to use 
 * @param <G1Element> The type of G1 Elements, where G1 x G2 -> GT
 * @param <G2Element> The type of G2 Elements
 * @param <GTElement> The type of GT Elements
 */
public interface Pairing
<
  P,
  G1Element extends Point<FqElement<P>, Fq<P>>,
  G2Element extends Point<Fq2Element<P>,Fq2<P>>,
  GTElement extends PairingResult<P>
>
{
  /**
   * Performs an asymmetric bilinear pairing operation. Note that for
   * symmetric pairings, the parameterization has to be adapted to a more
   * general way.
   * 
   * See, for example, "An Introduction to Pairing-Based Cryptography" 
   * (Menezes), "On Computable Isomorphisms in Efficient Asymmetric Pairing
   * Based Systems" (Smart, Vercauteren) and/or "The Eta Pairing Revisited"
   * (Hess, Smart, Vercauteren) for more or less general pairing
   * introductions.
   * 
   * @param Q A point, Element of G2
   * @param P A point, Element of G1
   * 
   * @return The pairing result, Element of GT
   */
  public GTElement pairing(G2Element Q, G1Element P);
  
  /**
   * Returns the group G1
   * 
   * @return G1
   */
  public CurveField<FqElement<P>, Fq<P>> getG1();

  /**
   * Returns the group G2
   * 
   * @return G2
   */
  public CurveField<Fq2Element<P>, Fq2<P>> getG2();

  /**
   * Returns the group GT
   * 
   * @return GT
   */
  public Field<Fq12Element<P>, Fq12<P>> getGT();
  
  /**
   * Getter for the rng
   * 
   * @return The rng
   */
  public Random getRandom();
}
