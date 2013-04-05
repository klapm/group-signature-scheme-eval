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

package org.iso200082.common.ecc.elements;


import java.math.BigInteger;

import org.iso200082.common.ecc.api.FieldElement;
import org.iso200082.common.ecc.api.TowerFieldElement;
import org.iso200082.common.ecc.elements.doubleprecision.FqDoubleElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;


/**
 * Single precision Fq Element. Abstract base to be implemented by the
 * underlying primitive implementations.
 * 
 * See Interface for a description of overridden methods, and especially
 * {@link TowerFieldElement} for the algorithm source(s).  
 * 
 * @see FieldElement
 * @see TowerFieldElement
 * @see Fq
 * @see FqDoubleElement
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public abstract class FqElement
<
  P
>
extends TowerFieldElement<FqElement<P>, FqDoubleElement<P>, Fq<P>>
{
  /** value representation */
  public P value;
  
  /**
   * Ctor, creates a new element using the given field and value
   * 
   * @param target_field The corresponding field
   * @param value The element's value
   */
  public FqElement(Fq<P> target_field, P value)
  {
    super(target_field);
    this.value = value;
  }
    
  @Override
  public String toString()
  {
    return toString(10);
  }
  
  @Override
  public String toString(int radix)
  {
    return toBigInteger().toString(radix);
  }
  
  @Override
  public abstract boolean equals(Object obj);
  
  @Override
  public abstract FqElement<P> clone();
  
  /**
   * Gets the element's value as a {@link BigInteger}
   * 
   * @return The element as {@link BigInteger}
   */
  public abstract BigInteger toBigInteger();
  
  /**
   * Computes this + in
   * 
   * @param in The element to add
   * 
   * @return this + in
   */
  public abstract FqElement<P> addNoReductionMutable(FqElement<P> in);
  
  /**
   * Computes this - in
   * 
   * @param in The element to subtract from this
   * 
   * @return this - in
   */
  public abstract FqElement<P> subNoReductionMutable(FqElement<P> in);
  
  /**
   * Division by two mod q
   * 
   * @return a new instance, representing this/2 mod q
   */
  public abstract FqElement<P> divByTwo();

  /**
   * Division by two mod q, mutable.
   * 
   * @return this/2 mod q
   */
  public abstract FqElement<P> divByTwoMutable();
  
  /**
   * Division by four mod q
   * 
   * @return a new instance, representing this/4 mod q
   */
  public abstract FqElement<P> divByFour();

  /**
   * Division by four mod q
   * 
   * @return this/4 mod q
   */
  public abstract FqElement<P> divByFourMutable();
}
