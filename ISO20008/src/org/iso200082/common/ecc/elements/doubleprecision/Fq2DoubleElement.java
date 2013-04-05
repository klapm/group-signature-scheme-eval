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

import org.iso200082.common.ecc.api.DoubleFieldElement;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.fields.towerextension.Fq2;
import org.iso200082.common.util.Util;

/**
 * Double precision Fq2 Element. 
 * See Interface for a description of overridden methods.
 * 
 * @see DoubleFieldElement
 * @see Fq2
 * @see Fq2Element
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Fq2DoubleElement
<
  P
>
implements DoubleFieldElement<Fq2DoubleElement<P>, Fq2Element<P>, Fq2<P>>
{
  /** The corresponding field */
  protected Fq2<P> field;
  
  /** Coefficient a */
  public FqDoubleElement<P> a;
  
  /** Coefficient b */
  public FqDoubleElement<P> b;

  /**
   * Ctor, initializes a and b to to x and y (respectively).
   * 
   * @param target_field The corresponding field
   * @param x Coefficient 0 (numbered left to right)
   * @param y Coefficient 1 (numbered left to right)
   */
  public Fq2DoubleElement(Fq2<P> target_field, FqDoubleElement<P> x, FqDoubleElement<P> y)
  {
    field = target_field;
    a = x;
    b = y;
  }

  @Override
  public byte[] toByteArray()
  {
    return Util.concatArrays(a.toByteArray(), b.toByteArray());
  }

  @Override
  public String toString()
  {
    return toString(10);
  }

  @Override
  public String toString(int radix)
  {
    return "Fq2Double([" + a.toString(radix) + ", " + b.toString(radix) + "])";
  }

  @Override
  public Fq2DoubleElement<P> add(Fq2DoubleElement<P> element)
  {
    return field.getDoubleElement(a.add(element.a), b.add(element.b));
  }

  @Override
  public Fq2DoubleElement<P> sub(Fq2DoubleElement<P> element)
  {
    return field.getDoubleElement(a.sub(element.a), b.sub(element.b));
  }

  @Override
  public Fq2Element<P> mod()
  {
    return field.getElement(a.mod(), b.mod());
  }

  @Override
  public Fq2<P> getField()
  {
    return field;
  }

  /**
   * Multiplication by xi.
   * F(q^12) = F(q^6)[w]/(w^2-gamma), F(q^6) = F(q^2)[gamma]/(gamma^3-xi) and
   * F(q^2) = F(q)[u](u^2-beta)
   * 
   * u = sqrt(-1), xi = 1 + u, (a + bu)(1 + u) = (a - b) + (a + b)u
   * 
   * @return A double-precision instance representing this * xi
   */
  public Fq2DoubleElement<P> mulXi()
  {
    return field.getDoubleElement(a.sub(b), a.add(b));
  }

  /**
   * Mutable multiplication by xi, see {@link #mulXi()}.
   * 
   * @return this * xi
   */
  public Fq2DoubleElement<P> mulXiMutable()
  {
    FqDoubleElement<P> tmp = a.clone();
    a.subMutable(b);
    b.addMutable(tmp);
    tmp.recycle();
    return this;
  }

  @Override
  public Fq2DoubleElement<P> twice()
  {
    return add(this);
  }

  @Override
  public Fq2DoubleElement<P> clone()
  {
    return field.getDoubleElement(a, b);
  }

  @Override
  public boolean isZero()
  {
    return a.isZero() && b.isZero();
  }

  @Override
  public boolean isOne()
  {
    return a.isOne() && b.isZero();
  }

  @Override
  public Fq2DoubleElement<P> twiceMutable()
  {
    return addMutable(this);
  }

  @Override
  public Fq2DoubleElement<P> addMutable(Fq2DoubleElement<P> element)
  {
    a.addMutable(element.a);
    b.addMutable(element.b);
    return this;
  }

  @Override
  public Fq2DoubleElement<P> subMutable(Fq2DoubleElement<P> element)
  {
    a.subMutable(element.a);
    b.subMutable(element.b);
    return this;
  }
    
  @Override
  public boolean equals(Object obj)
  {
    if(obj == this)
      return true;
    
    if(!(obj instanceof Fq2DoubleElement))
      return false;
    
    @SuppressWarnings("unchecked")
    Fq2DoubleElement<P> other = (Fq2DoubleElement<P>) obj;
    return a.equals(other.a) && b.equals(other.b);
  }
  
  @Override
  public void recycle()
  {
    field.recycle(this);
    a.recycle();
    b.recycle();
  }
}
