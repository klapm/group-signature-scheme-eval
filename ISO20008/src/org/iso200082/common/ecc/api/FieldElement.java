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

import java.math.BigInteger;

/**
 * Single-Precision field element interface. Somewhat parallel to
 * {@link DoubleFieldElement} since it supports more operations and deriving
 * it from {@link DoubleFieldElement} would result in quite unpleasant
 * type parameter chains..
 * 
 * Note that all elements implementing this interface should be (and are as
 * of now) <strong>immutable</strong>.
 * 
 * @see DoubleFieldElement
 * @see Element
 * @see TowerFieldElement
 * 
 * @param <E> The element's type
 * @param <F> The associated field's type
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface FieldElement
<
  E extends FieldElement<E, F>,
  F extends Field<? extends E, F>
>
extends Element<E, F>, Cloneable
{
  /**
   * Computes this + element.
   * 
   * @param element Some element to add to this
   * 
   * @return A new element, representing this + element
   */
  public E add(final E element);

  /**
   * Computes this = this + element.
   * 
   * @param element Some element to add to this
   * 
   * @return this (this = this + element)
   */
  public E addMutable(final E element);
  
  /**
   * Computes this - element.
   * 
   * @param element Some element to subtract from this
   * 
   * @return A new element, representing this - element
   */
  public E sub(final E element);
  
  /**
   * Computes this = this - element.
   * 
   * @param element Some element to subtract from this
   * 
   * @return this (this = this - element)
   */
  public E subMutable(final E element);
  
  /**
   * Computes this * element.
   * 
   * @param element Some element to multiply onto this
   * 
   * @return A new element, representing this * element
   */
  public E mul(final E element);

  /**
   * Computes this = this * element.
   * 
   * @param element Some element to multiply onto this
   * 
   * @return this (this = this * element)
   */
  public E mulMutable(final E element);

  /**
   * Computes this * bi. Note that the given {@link BigInteger} is not
   * transformed if working with a montgomery-variant as underlying "engine".
   * 
   * @param bi Some {@link BigInteger} to multiply onto this
   * 
   * @return A new element, representing this * bi
   */
  public E mul(final BigInteger bi);
  
  /**
   * Computes this = this * bi. Note that the given {@link BigInteger} is not
   * transformed if working with a montgomery-variant as underlying "engine".
   * 
   * @param bi Some {@link BigInteger} to multiply onto this
   * 
   * @return this (this = this * bi)
   */
  public E mulMutable(final BigInteger bi);
  
  /**
   * Computes -this.
   * 
   * @return A new element, representing -this
   */
  public E negate();

  /**
   * Computes this = -this.
   * 
   * @return this (this = -this)
   */
  public E negateMutable();
  
  /**
   * Computes 1/this.
   * 
   * @return A new element, representing 1/this
   */
  public E invert();
  
  /**
   * Computes 1/this.
   * 
   * @return this (this = 1/this)
   */
  public E invertMutable();
  
  /**
   * Computes this^2
   * 
   * @return A new element, representing this^2
   */
  public E square();  

  /**
   * Computes this = this^2
   * 
   * @return this (this = this^2)
   */
  public E squareMutable();
  
  /**
   * Computes this + this
   * 
   * @return A new element, representing this + this
   */
  public E twice();  

  /**
   * Computes this = this + this
   * 
   * @return this (this = this + this)
   */
  public E twiceMutable();
  
  /**
   * Computes this^exponent
   * 
   * @param exponent The exponent
   * 
   * @return A new element, representing this^exponent
   */
  public E pow(final BigInteger exponent);

  /**
   * Computes sqrt(this)
   * 
   * @return A new element, representing sqrt(this)
   */
  public E sqrt();

  /**
   * Computes this = sqrt(this)
   * 
   * @return this (this = sqrt(this))
   */
  public E sqrtMutable();
  
  /**
   * Copies this instance
   * 
   * @return A copy of this instance
   */
  public E clone();
  
  /**
   * Mutable division by two mod q
   * 
   * @return this/2 mod q
   */
  public E divByTwoMutable();
  
  /**
   * recycles all "contained" instances. That is, internal int[]s and so on
   * are put into a pool of reusable objects.
   */
  public abstract void recycle();
}
