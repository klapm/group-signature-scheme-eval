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
import org.iso200082.common.ecc.elements.Fq12Element;
import org.iso200082.common.ecc.fields.towerextension.Fq12;
import org.iso200082.common.util.Util;

/**
 * Double precision Fq12 Element. Actually, I don't think it's used anywhere
 * since no higher stacks than up to Fq12 were built until now, but it's
 * here for the sake of completion.
 * 
 * See Interface for a description of overridden methods.
 * 
 * @see DoubleFieldElement
 * @see Fq12
 * @see Fq12Element
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0 
 */
public class Fq12DoubleElement
<
  P
>
implements DoubleFieldElement<Fq12DoubleElement<P>, Fq12Element<P>, Fq12<P>>
{
  /** The corresponding field */
  protected Fq12<P> field;
  
  /** coefficient a */
  public Fq6DoubleElement<P> a;
  
  /** coefficient b */
  public Fq6DoubleElement<P> b;

  /**
   * Ctor, initializes a and b to the given values
   * 
   * @param target_field The corresponding field
   * @param c0 Coefficient 0 (numbered left to right)
   * @param c1 Coefficient 1 (numbered left to right)
   */
  public Fq12DoubleElement(Fq12<P> target_field, Fq6DoubleElement<P> c0, 
                                                 Fq6DoubleElement<P> c1)
  {
    field = target_field;
    a = c0;
    b = c1;
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
    return "Fq12Double([\n" + a.toString(radix) + ",\n"
                            + b.toString(radix) + "\n])";
  }

  @Override
  public Fq12DoubleElement<P> add(Fq12DoubleElement<P> element)
  {
    return field.getDoubleElement(a.add(element.a), b.add(element.b));
  }

  @Override
  public Fq12DoubleElement<P> sub(Fq12DoubleElement<P> element)
  {
    return field.getDoubleElement(a.sub(element.a), b.sub(element.b));
  }

  @Override
  public Fq12Element<P> mod()
  {
    return field.getElement(a.mod(), b.mod());
  }

  @Override
  public Fq12<P> getField()
  {
    return field;
  }

  @Override
  public Fq12DoubleElement<P> twice()
  {
    return add(this);
  }

  @Override
  public Fq12DoubleElement<P> clone()
  {
    return field.getDoubleElement(a.clone(), b.clone());
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
  public Fq12DoubleElement<P> twiceMutable()
  {
    return addMutable(this);
  }

  @Override
  public Fq12DoubleElement<P> addMutable(Fq12DoubleElement<P> element)
  {
    a.addMutable(element.a);
    b.addMutable(element.b);
    return this;
  }

  @Override
  public Fq12DoubleElement<P> subMutable(Fq12DoubleElement<P> element)
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
    
    if(!(obj instanceof Fq12DoubleElement))
      return false;
    
    @SuppressWarnings("unchecked")
    Fq12DoubleElement<P> other = (Fq12DoubleElement<P>) obj;
    return a.equals(other.a) && b.equals(other.b);
  }
  
  @Override
  public void recycle()
  {
    a.recycle();
    b.recycle();
    field.recycle(this);
  }

}
