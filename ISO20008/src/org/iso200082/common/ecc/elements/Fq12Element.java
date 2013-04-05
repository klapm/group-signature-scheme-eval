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

package org.iso200082.common.ecc.elements;


import java.math.BigInteger;

import org.iso200082.common.ecc.api.FieldElement;
import org.iso200082.common.ecc.api.PairingResult;
import org.iso200082.common.ecc.api.TowerFieldElement;
import org.iso200082.common.ecc.elements.doubleprecision.Fq12DoubleElement;
import org.iso200082.common.ecc.elements.doubleprecision.Fq6DoubleElement;
import org.iso200082.common.ecc.fields.towerextension.Fq12;
import org.iso200082.common.util.Util;


/**
 * Single precision Fq12 Element.
 * 
 * See Interface for a description of overridden methods, and especially
 * {@link TowerFieldElement} for the algorithm source(s).  
 * 
 * @see FieldElement
 * @see TowerFieldElement
 * @see PairingResult
 * @see Fq12
 * @see Fq12DoubleElement
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Fq12Element
<
  P
>
extends TowerFieldElement<Fq12Element<P>, Fq12DoubleElement<P>, Fq12<P>>
implements PairingResult<P>
{  
  /** coefficient a */
  public Fq6Element<P> a;

  /** coefficient b */
  public Fq6Element<P> b;
  
  /**
   * Ctor, initializes a and b to zero.
   * 
   * @param target_field The corresponding field
   */
  public Fq12Element(Fq12<P> target_field)
  {
    super(target_field);
    a = field.getBaseField().getZeroElement();
    b = field.getBaseField().getZeroElement();
  }

  /**
   * Ctor, initializes a and b to the given values
   * 
   * @param target_field The corresponding field
   * @param e1 Coefficient 0 (numbered left to right)
   * @param e2 Coefficient 1 (numbered left to right)
   */
  public Fq12Element(Fq12<P> target_field, Fq6Element<P> e1, Fq6Element<P> e2)
  {
    super(target_field);
    a = e1;
    b = e2;
  }

  @Override
  public Fq12Element<P> add(Fq12Element<P> element)
  {
    // algorithm 18 [Beuchat et al.]
    
    return field.getElement(a.add(element.a), b.add(element.b));
  }

  @Override
  public Fq12Element<P> sub(Fq12Element<P> element)
  {
    // algorithm 19 [Beuchat et al.]
    
    return field.getElement(a.sub(element.a), b.sub(element.b));
  }

  @Override
  public Fq12Element<P> mul(Fq12Element<P> element)
  {
    // algorithm 4 [Aranha et al.]
        
    Fq6DoubleElement<P> T0 = a.mulDouble(element.a);
    Fq6DoubleElement<P> T1 = b.mulDouble(element.b);
    
    Fq6Element<P> t0 = a.add(b);
    Fq6Element<P> t1 = element.a.add(element.b);
    
    Fq6DoubleElement<P> tmp = t0.mulDouble(t1);
    Fq6DoubleElement<P> T2  = T0.add(T1);
    
    Fq6Element<P> outb = tmp.subMutable(T2).mod();
    Fq6Element<P> outa = T1.mulGammaAddMutable(T0).mod();
    
    T0.recycle(); T1.recycle(); T2.recycle(); tmp.recycle();
    t0.recycle(); t1.recycle();
    return field.getElement(outa, outb);
  }

  @Override
  public Fq12Element<P> negate()
  {
    return field.getElement(a.negate(), b.negate());
  }

  @Override
  public Fq12Element<P> invert()
  {
    // algorithm 23 [Beuchat et al.]
    
    Fq6Element<P> tmp0, tmp1;
    Fq2Element<P> tmp2;
    
    tmp0   = a.square();
    tmp1   = b.square();
    tmp2   = tmp1.c.mulXiMutable();
    tmp0.a = tmp0.a.subMutable(tmp2);
    tmp0.b = tmp0.b.subMutable(tmp1.a);
    tmp0.c = tmp0.c.subMutable(tmp1.b);
    tmp0   = tmp0.invertMutable();    
    Fq6Element<P> outa  = a.mul(tmp0);
    Fq6Element<P> outb  = tmp0.mulMutable(b).negateMutable();

    tmp2.recycle();
    return field.getElement(outa, outb);
  }

  @Override
  public Fq12Element<P> addNoReduction(Fq12Element<P> element)
  {
    return field.getElement(a.addNoReduction(element.a),
                                  b.addNoReduction(element.b));
  }

  @Override
  public Fq12Element<P> subNoReduction(Fq12Element<P> element)
  {
    return field.getElement(a.subNoReduction(element.a),
                                  b.subNoReduction(element.b));
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
    return "Fq12([\n" + a.toString(radix) + ",\n"
                      + b.toString(radix) + "])";
  }

  @Override
  public Fq12<P> getField()
  {
    return field;
  }

  @Override
  public Fq12Element<P> square()
  {
    // Algorithm 5 [Aranha et al.]
    
    Fq6Element<P> t0, t1;
    
    t0 = a.add(b);
    t1 = b.mulGammaAdd(a);
    Fq6Element<P> outb = b.mul(a);
    Fq6Element<P> outa = t0.mulMutable(t1);
    
    outa.subMutable(outb.mulGammaAdd(outb));
    outb.twiceMutable();
    
    return field.getElement(outa, outb);
  }

  @Override
  public Fq12DoubleElement<P> mulDouble(Fq12Element<P> element)
  {
    /*
     * You might need/want to implement this if you require higher tower-stacks.
     */
    throw new UnsupportedOperationException("Not implemented");
  }
  
  @Override
  public Fq12DoubleElement<P> squareDouble()
  {
    /*
     * You might need/want to implement this if you require higher tower-stacks.
     */
    throw new UnsupportedOperationException("Not implemented");
  }

  @Override
  public Fq12Element<P> twice()
  {
    return add(this);
  }

  @Override
  public Fq12Element<P> twiceNoReduction()
  {
    return addNoReduction(this);
  }
  
  @Override
  @SuppressWarnings("unchecked")
  public boolean equals(Object obj)
  {
    if(obj == this)
      return true;
    
    if(!(obj instanceof Fq12Element))
      return false;
    
    Fq12Element<P> other = (Fq12Element<P>) obj;
    return other.a.equals(a) && other.b.equals(b);
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
  public Fq12Element<P> sqrt()
  {
    /*
     * You might need/want to implement this if you require higher tower-stacks.
     */
    throw new UnsupportedOperationException("Not implemented");
  }

  @Override
  public Fq12Element<P> mul(BigInteger bi)
  {
    return field.getElement(a.mul(bi), b.mul(bi));
  }

  @Override
  public Fq12Element<P> mulMutable(Fq12Element<P> element)
  {
    // algorithm 4 [Aranha et al.]
        
    Fq6DoubleElement<P> T0 = a.mulDouble(element.a);
    Fq6DoubleElement<P> T1 = b.mulDouble(element.b);
    
    Fq6Element<P> t0 = a.add(b);
    Fq6Element<P> t1 = element.a.add(element.b);
    
    Fq6DoubleElement<P> tmp = t0.mulDouble(t1);
    Fq6DoubleElement<P> T2  = T0.add(T1);
    
    b = tmp.subMutable(T2).mod();
    a = T1.mulGammaAddMutable(T0).mod();
    
    tmp.recycle(); T0.recycle(); T1.recycle(); T2.recycle(); 
    t0.recycle(); t1.recycle();
    return this;
  }

  @Override
  public Fq12Element<P> mulMutable(BigInteger bi)
  {
    a.mulMutable(bi);
    b.mulMutable(bi);
    return this;
  }

  @Override
  public Fq12Element<P> addMutable(Fq12Element<P> element)
  {
    a.addMutable(element.a); b.addMutable(element.b);
    return this;
  }

  @Override
  public Fq12Element<P> subMutable(Fq12Element<P> element)
  {
    a.subMutable(element.a); b.subMutable(element.b);
    return this;
  }

  @Override
  public Fq12Element<P> invertMutable()
  {
    // algorithm 23 [Beuchat et al.]
    
    Fq6Element<P> tmp0, tmp1;
    Fq2Element<P> tmp2;
    
    tmp0   = a.square();
    tmp1   = b.square();
    tmp2   = tmp1.c.mulXiMutable();
    tmp0.a = tmp0.a.subMutable(tmp2);
    tmp0.b = tmp0.b.subMutable(tmp1.a);
    tmp0.c = tmp0.c.subMutable(tmp1.b);
    tmp0   = tmp0.invertMutable();    
    a      = a.mulMutable(tmp0);
    b      = b.mulMutable(tmp0).negateMutable();
    
    tmp2.recycle();
    tmp0.recycle();
    return this;
  }

  @Override
  public Fq12Element<P> twiceMutable()
  {
    return addMutable(this);
  }

  @Override
  public Fq12Element<P> negateMutable()
  {
    a.negateMutable();
    b.negateMutable();
    return this;
  }

  @Override
  public Fq12Element<P> squareMutable()
  {
    // Algorithm 5 [Aranha et al.]
    
    Fq6Element<P> t0, t1;
    
    t0 = a.add(b);
    t1 = b.mulGammaAdd(a);
    b  = b.mulMutable(a);
    a  = t0.mulMutable(t1);
    t1.recycle();
    t1 = b.mulGammaAdd(b);
    
    a.subMutable(t1);
    b.twiceMutable();
    
    return this;
  }

  @Override
  public Fq12Element<P> sqrtMutable()
  {
    /*
     * You might need/want to implement this if you require higher tower-stacks.
     */
    throw new UnsupportedOperationException("Not implemented");
  }

  @Override
  public Fq12Element<P> clone()
  {
    return field.getElement(a.clone(), b.clone());
  }
  
  @Override
  public Fq12Element<P> divByTwoMutable()
  {
    a = a.divByTwoMutable();
    b = b.divByTwoMutable();
    return this;
  }
  
  @Override
  public void recycle()
  {
    field.recycle(this);
    a.recycle();
    b.recycle();
  }
}
