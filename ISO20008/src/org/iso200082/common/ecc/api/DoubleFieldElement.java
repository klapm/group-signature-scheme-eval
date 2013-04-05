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
 * Double-Precision elements. In this context, they are basically without
 * any bounds-checking (delayed montgomery reduction).
 * 
 * See "Faster Explicit Formulas for Computing Pairings over Ordinary Curves"
 * (Aranha, Karabina, Longa, Gebotys, López) and
 * for a discussion about the need of such elements.
 * 
 * They are less of a use in this implementation since {@link BigInteger}s
 * are used to store both the single- and double precision values but I wanted
 * to keep it seperate to avoid confusion (FqElements with values >> q are
 * somewhat strange, {@link TowerFieldElement#addNoReduction(TowerFieldElement)}
 * is bad enough already.
 *  
 * @param <E1> The element's type
 * @param <E2> The associated single-precision type
 * @param <F>  The associated field
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface DoubleFieldElement
<
  E1 extends DoubleFieldElement<E1, E2, F>,
  E2 extends TowerFieldElement<E2, E1, F>,
  F  extends Field<E2, F>
>
extends Element<E2, F>, Cloneable
{
  /**
   * Computes this + element. Does not perform
   * any bounds checking (might be negative or larger modulus).
   * 
   * @param element The other element
   * 
   * @return a new element, representing this + element
   */
  public E1 add(E1 element);
  
  /**
   * Computes this = this + element. Does not perform
   * any bounds checking (might be negative or larger modulus).
   * 
   * @param element The other element
   * 
   * @return this (this = this + element)
   */
  public E1 addMutable(E1 element);
  
  /**
   * Computes this - element. Does not perform
   * any bounds checking (might be negative or larger modulus).
   * 
   * @param element The other element
   * 
   * @return a new element, representing this - element
   */
  public E1 sub(E1 element);

  /**
   * Computes this = this - element. Does not perform
   * any bounds checking (might be negative or larger modulus).
   * 
   * @param element The other element
   * 
   * @return this (this = this - element)
   */
  public E1 subMutable(E1 element);
  
  /**
   * Doubles an element ("double" is a reserved keyword, so it's twice..).
   * Does not perform any bounds checking (might be negative or larger modulus).
   * 
   * @return a new element, representing this + this.
   */
  public E1 twice();

  /**
   * Doubles an element ("double" is a reserved keyword, so it's twice..)
   * in-place.
   * Does not perform any bounds checking (might be negative or larger modulus).
   * 
   * @return this (this = this + this).
   */
  public E1 twiceMutable();
  
  /**
   * Performs a reduction so it's back in the boundaries of Fq again,
   * thus return a single-precision element.
   * 
   * @return A single-precision element representing the reduced value
   */
  public E2 mod();
  
  /**
   * Copies the instance
   * 
   * @return a copy of the instance
   */
  public E1 clone();
  
  /**
   * recycles all "contained" instances. That is, internal int[]s and so on
   * are put into a pool of reusable objects.
   */
  public abstract void recycle();
  
}
