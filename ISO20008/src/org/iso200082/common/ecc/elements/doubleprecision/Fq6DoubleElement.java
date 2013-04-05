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
import org.iso200082.common.ecc.elements.Fq6Element;
import org.iso200082.common.ecc.fields.towerextension.Fq6;
import org.iso200082.common.util.Util;

/**
 * Double precision Fq6 Element.
 * 
 * See Interface for a description of overridden methods.
 * 
 * @see DoubleFieldElement
 * @see Fq6
 * @see Fq6Element
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Fq6DoubleElement
<
  P
>
implements DoubleFieldElement<Fq6DoubleElement<P>, Fq6Element<P>, Fq6<P>>
{
  
  /** The corresponding field */
  protected Fq6<P> field;
  
  /** coefficient a */
  public Fq2DoubleElement<P> a;
  
  /** coefficient b */
  public Fq2DoubleElement<P> b;
  
  /** coefficient c */
  public Fq2DoubleElement<P> c;

  /**
   * Ctor, initializes the coefficients a, b and c to c0, c1, c2 (respectively)
   * 
   * @param target_field The corresponding field
   * @param c0 Coefficient 0 (numbered left to right)
   * @param c1 Coefficient 1 (numbered left to right)
   * @param c2 Coefficient 2 (numbered left to right)
   */
  public Fq6DoubleElement(Fq6<P> target_field,    Fq2DoubleElement<P> c0,
                          Fq2DoubleElement<P> c1, Fq2DoubleElement<P> c2)
  {
    field = target_field;
    a = c0;
    b = c1;
    c = c2;
  }
  
  @Override
  public byte[] toByteArray()
  {
    return Util.concatArrays(a.toByteArray(), b.toByteArray(), c.toByteArray());
  }
  
  @Override
  public String toString()
  {
    return toString(10);
  }

  @Override
  public String toString(int radix)
  {
    return "Fq6Double([\n" + a.toString(radix) + ",\n"
                           + b.toString(radix) + ",\n"
                           + c.toString(radix) +  "\n])";
  }

  @Override
  public Fq6DoubleElement<P> add(Fq6DoubleElement<P> element)
  {
    return field.getDoubleElement(a.add(element.a), 
                                b.add(element.b), c.add(element.c));
  }

  @Override
  public Fq6DoubleElement<P> sub(Fq6DoubleElement<P> element)
  {
    return field.getDoubleElement(a.sub(element.a), 
                                b.sub(element.b), c.sub(element.c));
  }

  @Override
  public Fq6Element<P> mod()
  {
    return field.getElement(a.mod(), b.mod(), c.mod());
  }

  @Override
  public Fq6<P> getField()
  {
    return field;
  }
  
  /**
   * Algorithm 12 of "High-Speed Software Implementation of the Optimal Ate
   * Pairing over Barreto–Naehrig Curves" (Beuchat et al.), but adapted
   * such that it computes x * gamma + y. (Hence the shifted coefficients
   * in algorithm 11).
   * 
   * Stack:
   * F(q^12) = F(q^6)[w]/(w^2-gamma), F(q^6) = F(q^2)[gamma]/(gamma^3-xi) and
   * F(q^2) = F(q)[u](u^2-beta)
   * 
   * @param y The element to add
   * @return A new double-precision element representing x * gamma + y
   */
  public Fq6DoubleElement<P> mulGammaAdd(Fq6DoubleElement<P> y)
  {    
    Fq2DoubleElement<P> outa = c.mulXi().addMutable(y.a);
    Fq2DoubleElement<P> outb = a.add(y.b);
    Fq2DoubleElement<P> outc = b.add(y.c);
    return field.getDoubleElement(outa, outb, outc);
  }
  
  /**
   * Mutable variant of {@link #mulGammaAdd(Fq6DoubleElement)}.
   * 
   * @param y The element to add
   * @return A new double-precision element representing x * gamma + y
   */
  public Fq6DoubleElement<P> mulGammaAddMutable(Fq6DoubleElement<P> y)
  {    
    Fq2DoubleElement<P> tmpa = c.mulXiMutable().add(y.a);
    Fq2DoubleElement<P> tmpb = a.addMutable(y.b);
    c = b.addMutable(y.c);
    a = tmpa;
    b = tmpb;
    return this;
  }

  @Override
  public Fq6DoubleElement<P> twice()
  {
    return add(this);
  }

  @Override
  public Fq6DoubleElement<P> clone()
  {
    return field.getDoubleElement(a.clone(), b.clone(), c.clone());
  }

  @Override
  public boolean isZero()
  {
    return a.isZero() && b.isZero() && c.isZero();
  }

  @Override
  public boolean isOne()
  {
    return a.isOne() && b.isZero() && c.isZero();
  }

  @Override
  public Fq6DoubleElement<P> twiceMutable()
  {
    return addMutable(this);
  }

  @Override
  public Fq6DoubleElement<P> addMutable(Fq6DoubleElement<P> element)
  {
    a.addMutable(element.a);
    b.addMutable(element.b);
    c.addMutable(element.c);
    return this;
  }

  @Override
  public Fq6DoubleElement<P> subMutable(Fq6DoubleElement<P> element)
  {
    a.subMutable(element.a);
    b.subMutable(element.b);
    c.subMutable(element.c);
    return this;
  }
  
  @Override
  public boolean equals(Object obj)
  {
    if(obj == this)
      return true;
    
    if(!(obj instanceof Fq6DoubleElement))
      return false;
    
    @SuppressWarnings("unchecked")
    Fq6DoubleElement<P> other = (Fq6DoubleElement<P>) obj;
    return a.equals(other.a) && b.equals(other.b) && c.equals(other.c);
  }
  
  @Override
  public void recycle()
  {
    a.recycle();
    b.recycle();
    c.recycle();
    field.recycle(this);
  }

}
