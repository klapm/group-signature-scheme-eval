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

import java.math.BigInteger;
import java.util.Random;

import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.elements.doubleprecision.FqDoubleElement;

/**
 * Represents the finite base-field Fq.
 * 
 * See {@link Field} for interface-level descriptions and
 * {@link TowerExtensionField} for other overridden method descriptions.
 * 
 * @see Field
 * @see TowerExtensionField
 * @see FqElement
 * 
 * @param <P> The primitive Type to use 
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public abstract class Fq
<
  P
>
extends TowerExtensionField<FqElement<P>, FqElement<P>, Fq<P>, Fq<P>>
{  
  /** modulus << bitlength(modulus), see Aranha et al. */
  protected P qn;

  /** the modulus */
  protected BigInteger order;
    
  /** the non-montgomery variant (= this if already so) */
  protected Fq<P> nonmontgomery;
  
  /**
   * Ctor, initializes the field with given order.
   *  
   * @param random A {@link Random} instance
   * @param order The field's characteristic
   */
  public Fq(Random random, BigInteger order)
  {
    super(random, null);
    this.order = order;

    nonmontgomery = isMontgomery() ? getNonMontgomery() : this;
  }
  
  /**
   * Returns whether this fields transforms its elements into the montgomery
   * domain
   * 
   * @return true if so, false otherwise
   */
  public abstract boolean isMontgomery();
  
  /**
   * Returns the non-montgomery variant of this field
   * 
   * @return this if it is in non-montgomery mode, a non-montgomery variant 
   *         otherwise
   */
  protected abstract Fq<P> getNonMontgomery();
  
  /**
   * Returns a new instance using a given modulus
   * 
   * @param modulus The modulus to use
   * 
   * @return a new field instance
   */
  public abstract Fq<P> getNew(BigInteger modulus);
  
  /**
   * Returns a new non-montgomery variant of this field, using a given modulus
   * 
   * @param modulus The modulus to use
   * 
   * @return a new (non-montgomery) field instance
   */
  public abstract Fq<P> getNonMontgomery(BigInteger modulus);
  
  /**
   * Returns the element representing "2"
   * 
   * @return The two-element
   */
  public abstract FqElement<P> getTwoElement();
  
  /**
   * Reduces a double-precision element down to single precision using
   * the inherent modulus
   * 
   * @param dbl the double-precision element
   * 
   * @return The reduced single-precision element
   */
  public abstract FqElement<P> fromDouble(FqDoubleElement<P> dbl);
  
  /**
   * Getter for qn
   * @return (q << bitlen(q))
   */
  public P getQn()
  {
    return qn;
  }
   
  /**
   * Returns the non-montgomery variant of the field (if not already)
   * 
   * @return this if already non-montgomery, another non-montgomery instance 
   *         with the same modulus otherwise
   */
  public Fq<P> getNonMontgomeryField()
  {
    return nonmontgomery;
  }
  
  @Override
  public BigInteger getOrder()
  {
    return order;
  }

  @Override
  public int getNumberOfCoefficients()
  {
    return 1;
  }

  @Override
  public int getTotalNumberOfCoefficients()
  {
    return 1;
  }
}
