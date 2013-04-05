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
import org.iso200082.common.ecc.elements.doubleprecision.FqDoubleElement;
import org.iso200082.common.ecc.fields.towerextension.Fq2;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.common.util.Util;


/**
 * Single precision Fq2 Element.
 * 
 * See Interface for a description of overridden methods, and especially
 * {@link TowerFieldElement} for the algorithm source(s).  
 * 
 * @see FieldElement
 * @see TowerFieldElement
 * @see Fq2
 * @see Fq2DoubleElement
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Fq2Element
<
  P
>
extends TowerFieldElement<Fq2Element<P>, Fq2DoubleElement<P>, Fq2<P>>
{
  
  /** coefficient a */
  public FqElement<P> a;
  
  /** coefficient b */
  public FqElement<P> b;
  
  /**
   * Ctor, initializes both coefficients to zero.
   * 
   * @param target_field The corresponding field
   */
  public Fq2Element(Fq2<P> target_field)
  {
    super(target_field);
    a = field.getIrreducible().getField().getZeroElement();
    b = field.getIrreducible().getField().getZeroElement();
  }

  /**
   * Ctor, initializes both coefficients to the given values
   * 
   * @param target_field The corresponding field
   * @param c1 Coefficient 0 (numbered left to right)
   * @param c2 Coefficient 1 (numbered left to right)
   */
  public Fq2Element(Fq2<P> target_field, FqElement<P> c1, FqElement<P> c2)
  {
    super(target_field);
    a = c1;
    b = c2;
  }
  
  @Override
  public Fq2Element<P> add(Fq2Element<P> element)
  {
    // algorithm 5 [Beuchat et al.]
    
    return field.getElement(a.add(element.a), b.add(element.b));
  }

  @Override
  public Fq2Element<P> sub(Fq2Element<P> element)
  {
    // algorithm 6 [Beuchat et al.]

    return field.getElement(a.sub(element.a), b.sub(element.b));
  }

  @Override
  public Fq2Element<P> mul(Fq2Element<P> element)
  {
    // algorithm 2 [Aranha et al.], but with reduction
        
    FqElement<P> s  = a.addNoReduction(b);
    FqElement<P> t  = element.a.addNoReduction(element.b);
    FqDoubleElement<P> d0 = s.mulDouble(t);
    FqDoubleElement<P> d1 = a.mulDouble(element.a);
    FqDoubleElement<P> d2 = b.mulDouble(element.b);
    
    FqElement<P> outb = d0.subNoReductionMutable(d1)
                          .subNoReductionMutable(d2).mod();
    FqElement<P> outa = d1.subMutable(d2).mod();
    s.recycle();
    t.recycle();
    d0.recycle();
    d1.recycle();
    d2.recycle();
    return field.getElement(outa, outb);
  }

  /**
   * Computes this * c, where this is a Fq2Element and c is a FqElement.
   * So, basically, this.a * c and this.b * c is computed.
   * 
   * @param c The {@link FqElement} to multiply onto this
   * 
   * @return A new instance, representing this * c
   */
  public Fq2Element<P> mul(FqElement<P> c)
  {
    // algorithm 6 [Beuchat et al.]
    
    return field.getElement(a.mul(c), b.mul(c));
  }

  /**
   * Computes this = this * c, where this is a Fq2Element and c is a FqElement.
   * So, basically, this.a * c and this.b * c is computed.
   * 
   * @param c The {@link FqElement} to multiply onto this
   * 
   * @return this (this = this * c)
   */
  public Fq2Element<P> mulMutable(FqElement<P> c)
  {
    // algorithm 6 [Beuchat et al.]
    a.mulMutable(c);
    b.mulMutable(c);
    return this;
  }

  @Override
  public Fq2Element<P> mul(BigInteger x)
  {
    // algorithm 7 [Beuchat et al.]
    
    return field.getElement(a.mul(x), b.mul(x));
  }

  /**
   * Multiplication by xi.
   * F(q^12) = F(q^6)[w]/(w^2-v), F(q^6) = F(q^2)[v]/(v^3-xi) and
   * F(q^2) = F(q)[u](u^2-beta)
   * 
   * u = sqrt(-1), xi = 1 + u, (a + bu)(1 + u) = (a - b) + (a + b)u
   * 
   * @return A new instance representing this * xi
   */
  public Fq2Element<P> mulXi()
  {
    return field.getElement(a.sub(b), a.add(b));
  }

  /**
   * Mutable variant of {@link #mulXi()}.
   * 
   * @return this * xi
   */
  public Fq2Element<P> mulXiMutable()
  {
    FqElement<P> tmp = a.clone();
    a.subMutable(b);
    b.addMutable(tmp);
    return this;
  }

  /**
   * Division by two (taking loss due to cutoffs into account)
   * 
   * @return A new element representing this/2
   */
  public Fq2Element<P> divByTwo()
  {
    return field.getElement(a.divByTwo(), b.divByTwo());
  }

  /**
   * Division by two (taking loss due to cutoffs into account)
   * 
   * @return A new element representing this/2
   */
  public Fq2Element<P> divByTwoMutable()
  {
    a.divByTwoMutable();
    b.divByTwoMutable();
    return this;
  }
  
  /**
   * Division by four (taking loss due to cutoffs into account)
   * 
   * @return A new element representing this/4
   */
  public Fq2Element<P> divByFour()
  {
    return field.getElement(a.divByFour(), b.divByFour());
  }
  
  /**
   * In-place division by four
   * 
   * @return this (this = this / 4)
   */
  public Fq2Element<P> divByFourMutable()
  {
    a.divByFourMutable();
    b.divByFourMutable();
    return this;
  }
  
  @Override
  public Fq2Element<P> negate()
  {
    return field.getElement(a.negate(), b.negate());
  }

  @Override
  public Fq2Element<P> invert()
  {
    // algorithm 8 [Beuchat et al.]
    
    FqElement<P> outa, outb, aa, bb;
    
    aa    = a.square();
    bb    = b.square().addMutable(aa).invertMutable();
    outa  = a.mul(bb);
    outb  = b.negate().mulMutable(bb);
    aa.recycle();
    bb.recycle();
    return field.getElement(outa, outb);
  }

  @Override
  public Fq2Element<P> addNoReduction(Fq2Element<P> element)
  {
    return field.getElement(a.addNoReduction(element.a),
                            b.addNoReduction(element.b));
  }

  @Override
  public Fq2Element<P> subNoReduction(Fq2Element<P> element)
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
    return "Fq2([\n" + a.toString(radix) + ",\n"
                     + b.toString(radix) + "])";
  }

  @Override
  public Fq2Element<P> square()
  {
    // (a + bu)^2 = (a + b)(a - b) + 2abu
    FqElement<P> tt = a.sub(b);
    FqElement<P> outa = a.addNoReduction(b).mulMutable(tt);
    FqElement<P> outb = b.twiceNoReduction().mulMutable(a);
    tt.recycle();
    return field.getElement(outa, outb);
  }

  @Override
  public Fq2DoubleElement<P> mulDouble(Fq2Element<P> element)
  {
    return mulDouble(element, true);
  }
  
  /**
   * Computes this * element, resulting in a double-precision element (so no
   * reduction is performed).
   * 
   * @param element The element to multiply onto this
   * @param subnc Flag to indicate the optimization to use (see Aranha et al.)
   * 
   * @return A new double-precision element holding the result
   */
  public Fq2DoubleElement<P> mulDouble(Fq2Element<P> element, boolean subnc)
  {
    // algorithm 2 [Aranha et al.]
    
    FqElement<P> s = a.add(b);
    FqElement<P> t = element.a.add(element.b);
      
    FqDoubleElement<P> d0 = b.mulDouble(element.b);
    FqDoubleElement<P> outa = a.mulDouble(element.a);
    
    FqDoubleElement<P> outb = s.mulDouble(t);
    outb = outb.subMutable(outa).subMutable(d0);
      
    if(!subnc) // option 1/2, see [Aranha et al.], page 7
      outa = outa.addMutable(field.getBaseField().getQn()).subMutable(d0);
    else
      outa = outa.subMutable(d0);
      
    s.recycle(); t.recycle();
    d0.recycle();
    return field.getDoubleElement(outa, outb);
  }

  @Override
  public Fq2DoubleElement<P> squareDouble()
  {
    // Algorithm 7 [Aranha et al.]

    FqElement<P> apb = a.addNoReduction(b);
    FqElement<P> amb = a.subNoReduction(b);
    FqElement<P> ta  = a.twiceNoReduction();
    apb.recycle();
    amb.recycle();
    ta.recycle();
    // (a + bu)^2 = (a + b)(a - b) + 2abu
    return field.getDoubleElement(apb.mulDouble(amb),
                                   ta.mulDouble(b));
  }

  @Override
  public Fq2Element<P> twice()
  {
    return add(this);
  }

  @Override
  public Fq2Element<P> twiceNoReduction()
  {
    return addNoReduction(this);
  }

  @Override
  public boolean equals(Object obj)
  {
    if(obj == this)
      return true;
    
    if(!(obj instanceof Fq2Element))
      return false;
    
    @SuppressWarnings("unchecked")
    Fq2Element<P> other = (Fq2Element<P>) obj;
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
  public Fq2Element<P> sqrt()
  {
    return clone().sqrtMutable();
  }

  @Override
  public Fq2Element<P> mulMutable(Fq2Element<P> element)
  {
    // algorithm 2 [Aranha et al.], but with reduction

    FqElement<P> s  = a.addNoReduction(b);
    FqElement<P> t  = element.a.addNoReduction(element.b);
    FqDoubleElement<P> d0 = s.mulDouble(t);
    FqDoubleElement<P> d1 = a.mulDouble(element.a);
    FqDoubleElement<P> d2 = b.mulDouble(element.b);
    
    b.recycle();
    b = d0.subNoReductionMutable(d1).subNoReductionMutable(d2).mod();
    a = d1.subMutable(d2).mod();
    s.recycle();
    t.recycle();
    d0.recycle();
    d1.recycle();
    d2.recycle();
    return this;
  }

  @Override
  public Fq2Element<P> mulMutable(BigInteger element)
  {
    a.mulMutable(element);
    b.mulMutable(element);
    return this;
  }

  @Override
  public Fq2Element<P> addMutable(Fq2Element<P> element)
  {
    a.addMutable(element.a);
    b.addMutable(element.b);
    return this;
  }

  @Override
  public Fq2Element<P> subMutable(Fq2Element<P> element)
  {
    a.subMutable(element.a);
    b.subMutable(element.b);
    return this;
  }

  @Override
  public Fq2Element<P> invertMutable()
  {
    // algorithm 8 [Beuchat et al.]    
    FqElement<P> aa, bb;
    
    aa = a.square();
    bb = b.square().addMutable(aa).invertMutable();
    a.mulMutable(bb);
    b = b.negateMutable().mulMutable(bb);
    aa.recycle();
    bb.recycle();
    return this;
  }

  @Override
  public Fq2Element<P> twiceMutable()
  {
    return addMutable(this);
  }

  @Override
  public Fq2Element<P> negateMutable()
  {
    a.negateMutable();
    b.negateMutable();
    return this;
  }

  @Override
  public Fq2Element<P> squareMutable()
  {
    return mulMutable(this);
  }

  @Override
  public Fq2Element<P> sqrtMutable()
  {
    // see Michael Scott, 'Implementing Cryptographic Pairings'
    // ftp://136.206.11.249/pub/crypto/pairings.pdf
    
    FqElement<P> b_squared = b.square();
    FqElement<P> a_squared = a.square();
    
    FqElement<P> nb2   = field.getIrreducible().mul(b_squared);
    FqElement<P> a2nb2 = a_squared.sub(nb2);
    
    // returns null if no quadratic residue
    if(IntegerUtil.legendreSymbol(a2nb2.toBigInteger(),
       field.getBaseField().getOrder()) != 1) {
      return null;
    }
    
    Fq2Element<P> out = clone();
    FqElement<P>  tmp = a2nb2.sqrtMutable();
    if(tmp == null)
    {
      // try adding
      tmp = a_squared.addMutable(nb2).sqrtMutable();
      if(tmp == null)
        return null;
    }    
    
    a = out.a.sub(tmp).divByTwoMutable().sqrtMutable();
    if(a == null)
    {
      // try adding
      a = out.a.addMutable(tmp).divByTwoMutable().sqrtMutable();
      if(a == null)
        return null;
    }
    b = out.b.mulMutable(a.mul(a.getField().getTwoElement()).invertMutable());    
    return this;
  }

  @Override
  public Fq2Element<P> clone()
  {
    return field.getElement(a.clone(), b.clone());
  }

  @Override
  public void recycle()
  {
    a.recycle();
    b.recycle();
    field.recycle(this);
  }
}
