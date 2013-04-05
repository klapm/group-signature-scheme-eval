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

import org.iso200082.common.util.IntegerUtil;


/**
 * Top-Level Field-Element Interface. Provides functionality that is common
 * to all elements.
 * 
 * Note that all subclasses deriving from {@link Element} are <strong>
 * immutable</strong>.
 * 
 * @see FieldElement
 * @see DoubleFieldElement
 * 
 * @param <E> The element's type, needed for {@link #getField()}s F
 * @param <F> The field's type
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface Element
<
  E extends FieldElement<E, F>,
  F extends Field<? extends E, F>
>
{
  /**
   * Returns the field that is associated with the instance.
   * @return The corresponding field
   */
  public F getField();
  
  /**
   * Converts the Element to a byte-array, uses 
   * {@link IntegerUtil#i2bsp(java.math.BigInteger)} internally.
   * Concatenates all of the element's coefficients as fixed-length byte
   * arrays. The byte array length is given by the modulus' bit-length.
   * (The delta is due to addNoCarry in the {@link TowerFieldElement}s)
   * 
   * An element can be restored from a byte array using
   * {@link Field#getElementFromByteArray(byte[])}.
   * 
   * @return The element's byte array representation
   */
  public byte[] toByteArray();
  
  /**
   * String representation of the element. Uses base 10 as default (as
   * {@link BigInteger} does so), use {@link #toString(int)} for other
   * bases.
   * 
   * @return A {@link String} representation of the element
   */
  public String toString();
  

  /**
   * String representation of the element using a given base.
   * 
   * @param radix The base to use
   * 
   * @return A {@link String} representation of the element
   */
  public String toString(int radix);
  
  /**
   * Returns whether the element is zero.
   * 
   * @return true if zero, false otherwise
   */
  public boolean isZero();

  /**
   * Returns whether the element is one. Note that one is not necessarily '1'.
   * For example, if a montgomery-variant is used as arithmetic base for the
   * element, it might as well be R (2^(bit-length modulus)).
   * 
   * For polynomials, one == first coefficient is one, others zero.
   * 
   * @return true if one, false otherwise
   */
  public boolean isOne();

}
