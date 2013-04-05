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

import org.iso200082.common.ecc.fields.CurveField;
import org.iso200082.common.ecc.fields.towerextension.TowerExtensionField;

/**
 * Top-Level Field Interface. Provides functionality that is common
 * to all fields.
 * 
 * @see TowerExtensionField
 * @see CurveField
 * 
 * @param <E> The field's associated element's type
 * @param <F> The field itself
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface Field
<
  E extends FieldElement<E, F>,
  F extends Field<E, F>
>
{
  /**
   * Returns a random element within the range of that field.
   * 
   * @return A random element
   */
  public E getRandomElement();
  
  /**
   * Returns an element representing the one-element in this field
   * 
   * @return The one-element
   */
  public E getOneElement();

  /**
   * Returns an element representing the zero-element in this field
   * 
   * @return The zero-element
   */
  public E getZeroElement();
  
  /**
   * Creates an element from a given byte array. Compatible to
   * {@link Element#toByteArray()}. All elements need to be of equal length
   * (the length of the modulus).
   * 
   * @param data The byte array-representation of the element
   * 
   * @return The reconstructed element 
   */
  public E getElementFromByteArray(byte[] data);

  /**
   * Creates an element from the given components.
   * 
   * @param components The components (left-to-right, so the first 
   * 
   * @throws IllegalArgumentException if an invalid number of
   *         components is given
   * {@link BigInteger} is coefficient 0 of the highest-degree element)
   * 
   * @return The reconstructed element 
   */
  public E getElementFromComponents(BigInteger... components);
  
  /**
   * Creates an element from the given components.
   * 
   * @param components The components (left-to-right, so the first 
   * 
   * @throws IllegalArgumentException if an invalid number of
   *         components is given
   * long is coefficient 0 of the highest-degree element)
   * 
   * @return The reconstructed element 
   */
  public E getElementFromComponents(long... components);

  /**
   * Creates an element from the given components. Expects the {@link String}s
   * to be base 10, use {@link #getElementFromComponents(int, String...)} if
   * they're not.
   * 
   * @param components The components (left-to-right, so the first 
   * 
   * @throws IllegalArgumentException if an invalid number of
   *         components is given
   * {@link String} is coefficient 0 of the highest-degree element)
   * 
   * @return The reconstructed element 
   */
  public E getElementFromComponents(String... components);

  /**
   * Creates an element from the given components. Provides for {@link String}s
   * with bases != 10.
   * 
   * @param radix The base to use
   * @param components The components (left-to-right, so the first 
   * 
   * @throws IllegalArgumentException if an invalid number of
   *         components is given
   * {@link String} is coefficient 0 of the highest-degree element)
   * 
   * @return The reconstructed element 
   */
  public E getElementFromComponents(int radix, String... components);
  
  /**
   * Returns the fields order (number of elements)
   * 
   * @return The order as {@link BigInteger}
   */
  public BigInteger getOrder();

  /**
   * Returns the number of coefficients of this field's elements.
   * For tower stacks: Current level only, use
   * {@link #getTotalNumberOfCoefficients()} for the total amount.
   * 
   * E.g. for a Tower of Fq->Fq^2->Fq^6->Fq^12, the number of coefficients
   * for Fq12 Elements would be 2, whereas the total number would be 12.
   * 
   * @see #getTotalNumberOfCoefficients()
   * @return The number of coefficients
   */
  public int getNumberOfCoefficients();
  
  /**
   * Returns the total number of coefficients of this field's elements.
   * 
   * E.g. for a Tower of Fq->Fq^2->Fq^6->Fq^12, the number of coefficients
   * for Fq12 Elements would be 2, whereas the total number would be 12.
   *  
   * @see #getNumberOfCoefficients()
   * 
   * @return The total number of coefficients
   */
  public int getTotalNumberOfCoefficients();
  
}
