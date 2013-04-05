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

import org.iso200082.common.ecc.elements.AffinePoint;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.elements.ProjectivePoint;
import org.iso200082.common.ecc.fields.CurveField;

/**
 * Rudimentary point abstraction. 
 * 
 * See {@link AffinePoint} and {@link ProjectivePoint}.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 *
 * @param <E>
 * @param <F>
 */
public abstract class Point
<
  E extends FieldElement<E, F>,
  F extends Field<E, F>
>
implements FieldElement<Point<E, F>, CurveField<E, F>>
{

  /** The corresponding curvefield (not the element's field) */
  protected CurveField<E, F> field;
  
  /** infinite flag */
  public boolean infinite;
  
  /** x coord */
  public E x;
  
  /** y coord */
  public E y;

  /** z coord, unused in affine points */
  public E z;
  
  @Override
  public CurveField<E, F> getField()
  {
    return field;
  }
  
  @Override
  public abstract Point<E,F> clone();
  
  
  /**
   * Returns whether or not this point is infinite
   * 
   * @return true if infinite, false otherwise
   */
  public boolean isInfinite()
  {
    return infinite;
  }
  
  /**
   * Converts this point to a projective point (if not already)
   * 
   * @return this if already projective, the projective transformation otherwise
   */
  public abstract Point<E,F> toProjective();

  /**
   * Converts this point to an affine point (if not already)
   * 
   * @return this if already affine, the affine transformation otherwise
   */
  public abstract Point<E,F> toAffine();

  /**
   * Converts this point to an affine point (if not already) and stores
   * it in affine
   * 
   * @param affine the point to store the result to
   * 
   * @return the affine parameter
   */
  public abstract Point<E,F> toAffine(Point<E,F> affine);
  
  /**
   * returns whether or not this point is valid. That is, whether the
   * equation y^2 = x^3 + ax + b holds
   * 
   * @return true if valid, false otherwise
   */
  public abstract boolean isValid();
  
  /**
   * returns whether or not this point is in affine form.
   * 
   * @return true if affine, false otherwise
   */
  public abstract boolean isAffine();

  /**
   * Scalar multiplication, convenience wrapper for {@link #mul(BigInteger)}.
   * 
   * @param element The scalar to multiply with
   * @return A new point, representing [element]this
   */
  public abstract Point<E, F> mul(FqElement<?> element);
  
}
