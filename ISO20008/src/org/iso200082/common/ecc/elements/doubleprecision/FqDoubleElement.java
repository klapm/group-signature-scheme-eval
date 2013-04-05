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

package org.iso200082.common.ecc.elements.doubleprecision;

import java.math.BigInteger;

import org.iso200082.common.ecc.api.DoubleFieldElement;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;



/**
 * Double precision Fq Element. Abstract base to be implemented by the
 * underlying primitive implementations.
 * 
 * @see DoubleFieldElement
 * @see Fq
 * @see FqElement
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public abstract class FqDoubleElement
<
  P
>
implements DoubleFieldElement<FqDoubleElement<P>, FqElement<P>, Fq<P>>
{  
  /** It's internal value */
  public P value;
  
  /**
   * Ctor, initializes its value to the given one.
   * 
   * @param value        The target value
   */
  public FqDoubleElement(P value)
  {
    this.value = value;    
  }

  /**
   * 
   * Subtraction that subtracts element from 
   * this + (modulus << bitlength(modulus))
   * 
   * @param element The element to subtract
   * @return (this + (modulus << bitlength(modulus))) - element
   */
  public abstract FqDoubleElement<P> subOpt1(FqDoubleElement<P> element);
  
  /**
   * Subtraction without reduction.
   * 
   * @param element The element to subtract
   * 
   * @return this-element
   */
  public abstract FqDoubleElement<P> 
  subNoReductionMutable(FqDoubleElement<P> element);
  
  /**
   * Computes this + other
   * @param other
   * @return this + other
   */
  public abstract FqDoubleElement<P> addMutable(P other);
  
  /**
   * Gets the element's value as a {@link BigInteger}
   * 
   * @return The element as {@link BigInteger}
   */
  public abstract BigInteger toBigInteger();
  
  @Override
  public abstract FqDoubleElement<P> clone();
  
  @Override
  public String toString()
  {
    return toString(10);
  }

  @Override
  public String toString(int radix)
  {
    return "FqDouble(" + toBigInteger().toString(radix) + ")";
  }
  
  @Override
  public abstract boolean equals(Object obj);
}
