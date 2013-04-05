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

package org.iso200082.common.ecc.fields.towerextension;


import java.util.Random;

import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.api.FieldElement;


/**
 * Abstract base class for Tower extension fields. Common members and
 * methods are to be found here.
 *
 * @param <E1> The actual field's elements
 * @param <E2> The 'inner' elements (so the element's type of the underlying
 *             field), the type of the irreducible
 * @param <F1> The actual field
 * @param <F2> The 'inner' field
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public abstract class TowerExtensionField
<
  E1 extends FieldElement<E1, F1>,
  E2 extends FieldElement<E2, F2>,
  F1 extends Field<E1, F1>,
  F2 extends Field<E2, F2>
>
implements Field<E1, F1>
{
  /** The irreducible's coefficient
   * (not the whol polynomial but just the coefficient) */
  protected final E2 irreducible;
  
  /** A {@link Random} instance */
  protected Random rnd;
  
  
  /**
   * Ctor, initializes the {@link Random} instance and the poly coefficient.
   * 
   * @param random A {@link Random} instance
   * @param irreduciblePolyCoefficient The irreducible's coefficient, see
   * concrete types for some more explanations
   * 
   * @see Fq2
   * @see Fq6
   * @see Fq12
   */
  public TowerExtensionField(Random random, E2 irreduciblePolyCoefficient)
  {
    rnd         = random;
    irreducible = irreduciblePolyCoefficient;
  }

  /**
   * Getter for the irreducible polynomial coefficient (coeff. only!)
   * 
   * @return The coefficient
   */
  public E2 getIrreducible()
  {
    return irreducible;
  }

  /**
   * Getter for the base field (relative, so the layer directly below the
   * current field), but these getters can of course be chained..
   * 
   * @return The base field
   */
  public F2 getBaseField()
  {
    return irreducible.getField();
  }
  
  /**
   * Creates a field element by it's given coefficients.
   *         
   * @param elements The coefficients, ellipsis argument
   * 
   * @return The created element
   */
  @SuppressWarnings("unchecked") // i dare you
  public abstract E1 getElementFromComponents(E2... elements);
  
  /**
   * Returns a given element to the pool of available ones
   * 
   * @param element The element to recycle
   */
  public abstract void recycle(E1 element);
}
