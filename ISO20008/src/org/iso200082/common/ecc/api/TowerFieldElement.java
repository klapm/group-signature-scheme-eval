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
 * Superclass for tower extension field elements.
 * 
 * See Interface for a description of overridden methods, and especially
 * {@link TowerFieldElement} for the algorithm source(s).  
 * 
 * @see FieldElement
 * @see TowerFieldElement
 * 
 * @param <E> The element's type
 * @param <D> The associated double precision element's type
 * @param <F> The associated field
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public abstract class TowerFieldElement
<
  E extends TowerFieldElement<E, D, F>,
  D extends DoubleFieldElement<D, E, F>,
  F extends Field<E, F>
>
implements FieldElement<E, F>
{
  /** The corresponding field */
  protected F field;
  
  /**
   * Ctor, initializes the field
   * 
   * @param target_field The corresponding field
   */
  public TowerFieldElement(final F target_field)
  {
    field = target_field;
  }
  
  @Override
  public F getField()
  {
    return field;
  }
    
  /**
   * Computes this + element without a reduction check (so 'no carry' means
   * don't check whether the result is out of [0, order]).
   * 
   * @param element Some element to add to this
   * 
   * @return A new element, representing this + element
   */
  public abstract E addNoReduction(final E element);

  /**
   * Computes this - element without a reduction check (so 'no carry' means
   * don't check whether the result is out of [0, order]).
   * 
   * @param element Some element to subtract from this
   * 
   * @return A new element, representing this - element
   */
  public abstract E subNoReduction(final E element);

  /**
   * Computes this + this without a reduction check (so 'no carry' means
   * don't check whether the result is out of [0, order]).
   * 
   * @return A new element, representing this + this
   */
  public abstract E twiceNoReduction();
  
  /**
   * Computes this * element without any reduction, resulting in a double-
   * precision element.
   * 
   * @param element Some element to multiply onto this
   * 
   * @return A new double-precision element, representing this * element
   */
  public abstract D mulDouble(final E element);
  
  /**
   * Computes this * this without any reduction, resulting in a double-
   * precision element.
   *  
   * @return A new double-precision element, representing this * this
   */
  public abstract D squareDouble();

  @Override
  public E pow(final BigInteger exp)
  {
    E out = field.getOneElement();
    E x   = clone();
    for(int i = 0; i < exp.bitLength(); i++)
    {
      if(exp.testBit(i))
        out = out.mulMutable(x);
      
      x = x.squareMutable();
    }

    return out;
  }
  
  public abstract E clone();
}
