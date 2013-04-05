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
import org.iso200082.common.ecc.api.TowerFieldElement;
import org.iso200082.common.ecc.elements.doubleprecision.Fq2DoubleElement;
import org.iso200082.common.ecc.elements.doubleprecision.Fq6DoubleElement;
import org.iso200082.common.ecc.fields.towerextension.Fq6;
import org.iso200082.common.util.Util;

/**
 * Single precision Fq6 Element.
 * 
 * See Interface for a description of overridden methods, and especially
 * {@link TowerFieldElement} for the algorithm source(s).  
 * 
 * @see FieldElement
 * @see TowerFieldElement
 * @see Fq6
 * @see Fq6DoubleElement
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Fq6Element
<
  P
>
extends TowerFieldElement<Fq6Element<P>, Fq6DoubleElement<P>, Fq6<P>>
{
  /** coefficient a */
  public Fq2Element<P> a;
  
  /** coefficient b */
  public Fq2Element<P> b;

  /** coefficient c */
  public Fq2Element<P> c;

  /**
   * Ctor, intializes a, b and c to zero.
   * 
   * @param target_field The corresponding field
   */
  public Fq6Element(Fq6<P> target_field)
  {
    super(target_field);
    a = field.getIrreducible().getField().getZeroElement();
    b = field.getIrreducible().getField().getZeroElement();
    c = field.getIrreducible().getField().getZeroElement();
  }

  /**
   * Ctor, initializes the coefficients to the given values
   * 
   * @param target_field The corresponding field
   * @param c0 Coefficient 0 (numbered left to right)
   * @param c1 Coefficient 1 (numbered left to right)
   * @param c2 Coefficient 2 (numbered left to right)
   */
  public Fq6Element(Fq6<P> target_field, Fq2Element<P> c0, Fq2Element<P> c1, Fq2Element<P> c2)
  {
    super(target_field);
    a = c0;
    b = c1;
    c = c2;
  }
  
  @Override
  public Fq6Element<P> add(Fq6Element<P> element)
  {
    // Algorithm 10 [Beuchat et al.]
    return field.getElement(a.add(element.a), b.add(element.b), c.add(element.c));
  }

  @Override
  public Fq6Element<P> sub(Fq6Element<P> element)
  {
    // Algorithm 11 [Beuchat et al.]
    return field.getElement(a.sub(element.a), b.sub(element.b), c.sub(element.c));
  }

  @Override
  public Fq6Element<P> mul(Fq6Element<P> element)
  {
    // basically algorithm 3 [Aranha et al.], but single-precision
    
    Fq2Element<P> t0, t1, outa, outb, outc, T0, T1, T2;
    
    T0 = a.mul(element.a);
    T1 = b.mul(element.b);
    T2 = c.mul(element.c);
    
    t0 = b.add(c);
    t1 = element.b.add(element.c);
    
    outc  = t0.mulMutable(t1);
    outb  = T1.add(T2);
    outc  = outc.subMutable(outb);
    
    outb  = outc.mulXiMutable();
    outa  = outb.addMutable(T0);
    
    t0     = a.add(b);
    t1     = element.a.add(element.b);
    outc   = t0.mulMutable(t1);
    outb   = T0.add(T1);
    outc.a = outc.a.subMutable(outb.a);
    outc.b = outc.b.subMutable(outb.b);
    outb.a = T2.a.sub(T2.b);
    outb.b = T2.a.add(T2.b);
    
    outb   = outb.addMutable(outc);
    
    t0 = a.add(c);
    t1 = element.a.add(element.c);
    
    outc = t0.mulMutable(t1);
    
    T2 = T2.addMutable(T0);
    
    outc.a = outc.a.subMutable(T2.a);
    outc.a = outc.a.addMutable(T1.a);
    outc.b = outc.b.subMutable(T2.b);
    outc.b = outc.b.addMutable(T1.b);
   
    T1.recycle(); T2.recycle(); T0.recycle(); t1.recycle();
    return field.getElement(outa, outb, outc);
  }

  @Override
  public Fq6Element<P> negate()
  {
    return field.getElement(a.negate(), b.negate(), c.negate());
  }

  @Override
  public Fq6Element<P> invert()
  {
    // algorithm 17 [beuchat et al.]
    
    Fq2Element<P> outa, outb, outc, t0, t1, t2, t4, t5;
    
    t0    = b.mul(c);
    outa  = t0.mulXiMutable();
    t0    = a.square();
    outa  = t0.subMutable(outa);
    t1    = b.square();
    t5    = a.mul(c);
    outc  = t1.subMutable(t5);
    t2    = c.square();
    t4    = a.mul(b);
    outb  = t2.mulXiMutable().sub(t4);    
    t1    = a.mul(outa);
    t5    = c.mul(outb);
    t4    = t5.mulXiMutable();
    t1    = t1.addMutable(t4);
    t5    = b.mul(outc);
    t4    = t5.mulXiMutable();
    t1    = t1.addMutable(t4).invertMutable();
    outa  = outa.mulMutable(t1);
    outb  = outb.mulMutable(t1);
    outc  = outc.mulMutable(t1);
    
    return field.getElement(outa, outb, outc);
  }

  @Override
  public Fq6Element<P> addNoReduction(Fq6Element<P> element)
  {
    return field.getElement(a.addNoReduction(element.a),
                                 b.addNoReduction(element.b),
                                 c.addNoReduction(element.c));
  }

  @Override
  public Fq6Element<P> subNoReduction(Fq6Element<P> element)
  {
    return field.getElement(a.subNoReduction(element.a),
                                 b.subNoReduction(element.b),
                                 c.subNoReduction(element.c));
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
    return "Fq6([\n" + a.toString(radix) + ",\n"
                     + b.toString(radix) + ",\n"
                     + c.toString(radix) +  "\n])";
  }

  @Override
  public Fq6<P> getField()
  {
    return field;
  }

  @Override
  public Fq6Element<P> square()
  {
    // algorithm 16 [Beuchat et al.]
    
    Fq2Element<P> outa, outb, outc, v3, v4, v5;
    
    v4    = a.twice().mulMutable(b);
    v5    = c.square();
    outb  = v5.mulXi().addMutable(v4);
    outc  = v4.subMutable(v5);
    v3    = a.square();
    v4    = a.sub(b).addMutable(c);
    v5    = b.twice().mulMutable(c);
    v4    = v4.squareMutable();
    outa  = v5.mulXi().addMutable(v3);
    outc  = outc.addMutable(v4).addMutable(v5).subMutable(v3);
    
    v5.recycle(); v3.recycle(); v4.recycle();
    return field.getElement(outa, outb, outc);
  }

  @Override
  public Fq6DoubleElement<P> mulDouble(Fq6Element<P> element)
  {
    // algorithm 3 [Aranha et al.]
        
    Fq2Element<P> t0, t1;
    Fq2DoubleElement<P> outa, outb, outc, T0, T1, T2;
    
    T0 = a.mulDouble(element.a, false);
    T1 = b.mulDouble(element.b, false);
    T2 = c.mulDouble(element.c, false);
    
    t0 = b.add(c);
    t1 = element.b.add(element.c);
    
    outc  = t0.mulDouble(t1);
    outb  = T1.add(T2);
    outc  = outc.subMutable(outb);
    
    outb  = outc.mulXiMutable();
    outa  = outb.addMutable(T0);
    
    t0     = a.add(b);
    t1     = element.a.add(element.b);
    outc   = t0.mulDouble(t1);
    outb   = T0.add(T1);
    outc.a = outc.a.subMutable(outb.a);
    outc.b = outc.b.subMutable(outb.b);
    outb.a = T2.a.subOpt1(T2.b);
    outb.b = T2.a.add(T2.b);
    
    outb   = outb.addMutable(outc);
    
    t0 = a.add(c);
    t1 = element.a.add(element.c);
    
    outc = t0.mulDouble(t1);
    
    T2 = T2.addMutable(T0);
    
    outc.a = outc.a.subMutable(T2.a);
    outc.a = outc.a.addMutable(T1.a);
    outc.b = outc.b.subMutable(T2.b);
    outc.b = outc.b.addMutable(T1.b);
   
    T0.recycle(); T1.recycle(); T2.recycle(); t0.recycle(); t1.recycle();
    return field.getDoubleElement(outa, outb, outc);
  }

  @Override
  public Fq6DoubleElement<P> squareDouble()
  {
    return mulDouble(this);
  }

  @Override
  public Fq6Element<P> twice()
  {
    return add(this);
  }

  @Override
  public Fq6Element<P> twiceNoReduction()
  {
    return field.getElement(a.twiceNoReduction(), b.twiceNoReduction(), c.twiceNoReduction());
  }

  @Override
  @SuppressWarnings("unchecked")
  public boolean equals(Object obj)
  {
    if(obj == this)
      return true;
    
    if(!(obj instanceof Fq6Element))
      return false;
    
    Fq6Element<P> other = (Fq6Element<P>) obj;
    return other.a.equals(a) && other.b.equals(b) && other.c.equals(c);
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
   * @return A new element representing x * gamma + y
   */
  public Fq6Element<P> mulGammaAdd(Fq6Element<P> y)
  {
    Fq2Element<P> outa = c.mulXi().addMutable(y.a);
    Fq2Element<P> outb = a.add(y.b);
    Fq2Element<P> outc = b.add(y.c);
    
    return field.getElement(outa, outb, outc);
  }

  @Override
  public boolean isZero()
  {
    return a.isZero() && b.isZero();
  }

  @Override
  public boolean isOne()
  {
    return a.isOne() && b.isZero() && c.isZero();
  }

  @Override
  public Fq6Element<P> sqrt()
  {
    /*
     * You might need/want to implement this if you require higher tower-stacks.
     */
    throw new UnsupportedOperationException("Not implemented");
  }

  @Override
  public Fq6Element<P> mul(BigInteger bi)
  {
    return field.getElement(a.mul(bi), b.mul(bi), c.mul(bi));
  }

  @Override
  public Fq6Element<P> mulMutable(Fq6Element<P> element)
  {
    //return mulDouble(element).mod(); // optimize me.
    Fq2Element<P> t0, t1, outa, outb, outc, T0, T1, T2;
    
    T0 = a.mul(element.a);
    T1 = b.mul(element.b);
    T2 = c.mul(element.c);
    
    t0 = b.add(c);
    t1 = element.b.add(element.c);
    
    outc  = t0.mulMutable(t1);
    outb  = T1.add(T2);
    outc  = outc.subMutable(outb);

    t0     = a.add(b);
    b  = outc.mulXiMutable();
    outa  = b.addMutable(T0);
    
    t1     = element.a.add(element.b);
    outc   = t0.mulMutable(t1);
    b   = T0.add(T1);
    outc.a = outc.a.subMutable(b.a);
    outc.b = outc.b.subMutable(b.b);
    b.a = T2.a.sub(T2.b);
    b.b = T2.a.add(T2.b);
    
    b   = b.addMutable(outc);
    
    t0 = a.addMutable(c);
    t1 = element.a.add(element.c);
    
    c = t0.mulMutable(t1);
    
    T2 = T2.addMutable(T0);
    
    c.a = c.a.subMutable(T2.a);
    c.a = c.a.addMutable(T1.a);
    c.b = c.b.subMutable(T2.b);
    c.b = c.b.addMutable(T1.b);
    a = outa;
   
    T0.recycle(); T1.recycle(); T2.recycle(); t1.recycle();
    return this;
  }

  @Override
  public Fq6Element<P> mulMutable(BigInteger bi)
  {
    a.mulMutable(bi);
    b.mulMutable(bi);
    c.mulMutable(bi);
    return this;
  }

  @Override
  public Fq6Element<P> addMutable(Fq6Element<P> element)
  {
    a.addMutable(element.a); b.addMutable(element.b); c.addMutable(element.c);
    return this;
  }

  @Override
  public Fq6Element<P> subMutable(Fq6Element<P> element)
  {
    // Algorithm 11 [Beuchat et al.]
    a.subMutable(element.a); b.subMutable(element.b); c.subMutable(element.c);
    return this;
  }

  @Override
  public Fq6Element<P> invertMutable()
  {
    // algorithm 17 [beuchat et al.]
    
    Fq2Element<P> t0, t1, t2, t4, t5;
    Fq2Element<P> xa, xb, xc;
    
    t0    = b.mul(c);
    xa    = t0.mulXiMutable();
    t0    = a.square();
    xa    = t0.subMutable(xa);
    t1    = b.square();
    t5    = a.mul(c);
    xc    = t1.subMutable(t5);
    t2    = c.square();
    t4    = a.mul(b);
    xb    = t2.mulXiMutable().subMutable(t4);    
    t1    = a.mul(xa);
    t5    = c.mul(xb);
    t4    = t5.mulXiMutable();
    t1    = t1.addMutable(t4);
    t5    = b.mul(xc);
    t4    = t5.mulXiMutable();
    t1    = t1.addMutable(t4).invertMutable();
    a     = xa.mulMutable(t1);
    b     = xb.mulMutable(t1);
    c     = xc.mulMutable(t1);
    
    t4.recycle(); t1.recycle();
    return this;
  }

  @Override
  public Fq6Element<P> twiceMutable()
  {
    return addMutable(this);
  }

  @Override
  public Fq6Element<P> negateMutable()
  {
    a.negateMutable();
    b.negateMutable();
    c.negateMutable();
    return this;
  }

  @Override
  public Fq6Element<P> squareMutable()
  {
    // algorithm 16 [Beuchat et al.]
    
    Fq2Element<P> xb, xc;
    Fq2Element<P> v3, v4, v5;
    
    v4 = a.twice().mulMutable(b);
    v5 = c.square();
    xb = v5.mulXi().addMutable(v4);
    xc = v4.subMutable(v5);
    v3 = a.square();
    v4 = a.sub(b).addMutable(c);
    v5 = b.twice().mulMutable(c);
    v4 = v4.squareMutable();
    a  = v5.mulXi().addMutable(v3);
    c  = xc.addMutable(v4).addMutable(v5).subMutable(v3);
    b  = xb;
    
    v5.recycle(); v3.recycle();
    return this;
  }

  @Override
  public Fq6Element<P> sqrtMutable()
  {
    /*
     * You might need/want to implement this if you require higher tower-stacks.
     */
    throw new UnsupportedOperationException("Not implemented");
  }

  @Override
  public Fq6Element<P> clone()
  {
    return field.getElement(a.clone(), b.clone(), c.clone());
  }
  
  @Override
  public Fq6Element<P> divByTwoMutable()
  {
    a = a.divByTwoMutable();
    b = b.divByTwoMutable();
    c = c.divByTwoMutable();
    return this;
  }
  
  @Override
  public void recycle()
  {
    field.recycle(this);
    a.recycle();
    b.recycle();
    c.recycle();
  }

}
