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
import java.util.ArrayList;

import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.api.FieldElement;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.fields.CurveField;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.common.util.Util;


/**
 * Elliptic curve point, affine coordinates, immutable.
 * 
 * Supports addition, doubling and scalar multiplication.
 * 
 * @see FieldElement
 * @see CurveField
 * @see ProjectivePoint
 * @see Point
 * 
 * @param <E> The contained element's types (x,y)
 * @param <F> The element's field
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class AffinePoint
<
  E extends FieldElement<E, F>,
  F extends Field<E, F>
>
extends Point<E,F>
//implements FieldElement<Point<E, F>, CurveField<E, F>>
{
  /**
   * Ctor, initializes both x and y to zero (leading to point being infinite).
   * 
   * @param field The corresponding field
   */
  public AffinePoint(CurveField<E, F> field)
  {
    this.field = field;
    x = field.getField().getZeroElement();
    y = field.getField().getZeroElement();
    infinite = true;
  }

  /**
   * Ctor, initializes x and y to the given x and y. The values are verified and
   * the point is infinite if these values weren't ok (for this curve).
   * 
   * @param field The corresponding field
   * @param x Given x coordinate value
   * @param y Given y coordinate value
   */
  public AffinePoint(CurveField<E, F> field, E x, E y)
  {
    this.field = field;
    this.x = x;
    this.y = y;
    infinite = !isValid();
  }

  // does not copy
  /**
   * Ctor that does not copy. Used internally at {@link #clone()} and
   * {@link ProjectivePoint#toAffine()}.
   * 
   * @param field The corresponding field
   * @param x Given x coordinate value
   * @param y Given y coordinate value
   * @param inf Infinity flag
   */
  AffinePoint(CurveField<E, F> field, E x, E y, boolean inf)
  {
    this.field = field;
    this.x = x;
    this.y = y;
    infinite = inf;
  }

  /**
   * Creates a point from a given x coordinate, computes the corresponding
   * y coordinate.
   * 
   * Note that {@link FieldElement#sqrt()} has to be implemented for this to
   * work, which is only the case for {@link FqElement}s and
   * {@link Fq2Element}s for the moment.
   *  
   * @param field The corresponding field
   * @param x The x coordinate to compute y from
   */
  public AffinePoint(CurveField<E, F> field, E x)
  {
    this.field = field;
    
    setFromX(x.clone());
  }

  @Override
  public CurveField<E, F> getField()
  {
    return field;
  }

  @Override
  public byte[] toByteArray()
  {
    return Util.concatArrays(x.toByteArray(), y.toByteArray());
  }
  
  @Override
  public String toString()
  {
    return toString(10);
  }

  @Override
  public String toString(int radix)
  {
    return "AffinePt([" + x.toString(radix) + ", " 
                        + y.toString(radix) + "], "
                        + "infinite: " 
                        + (infinite ? "true" : "false")
                        + ")";
  }

  @Override
  public Point<E, F> add(Point<E, F> element)
  {
    return clone().addMutable(element);
  }

  @Override
  public Point<E, F> mul(Point<E, F> element)
  {
    return add(element);
  }
  
  @Override
  public AffinePoint<E, F> mul(FqElement<?> element)
  {
    return mul(element.toBigInteger());
  }
  
  /**
   * Scalar multiplication, computes [x]P (P == this).
   * Uses algorithm 3.36 (Window NAF method for point multiplication)
   * of "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone).
   * 
   * wNAF representation is computed in
   * {@link IntegerUtil#wnaf(BigInteger, byte)}
   * 
   * @see IntegerUtil
   * 
   * @param x The scalar to multiply with
   * @return A new point, representing [x]this
   */
  public AffinePoint<E, F> mul(BigInteger x)
  {
    return clone().mulMutable(x);
  }

  @Override
  public AffinePoint<E, F> mulMutable(BigInteger bi)
  {
    if(infinite || bi.equals(BigInteger.ONE))
      return this;

    if(bi.equals(BigInteger.ZERO)) {
      infinite = true;
      return this;
    }
            
    byte w = optimalPowWindowSize(bi);
    byte[] x_wnaf = IntegerUtil.wnaf(bi, w);
    
    ArrayList<Point<E, F>> P = new ArrayList<Point<E, F>>();
    P.add(clone());
    P.add(negate());
    Point<E, F> twoP = twice();
    for(int j = 1, i = 3; i < (1 << (w - 1)); i += 2, j+=2) {
      Point<E,F> tmp = P.get(j-1).add(twoP);
      P.add(tmp);
      P.add(tmp.negate());
    }

    infinite = true;
    if(field.useMixedModeMultiplication()) {
      Point<E,F> pt = new ProjectivePoint<E, F>(field);
      
      for(int i = x_wnaf.length - 1; i >= 0; i--)
      {
        pt.twiceMutable();
      
        if(x_wnaf[i] > 0) {
          pt.addMutable(P.get(x_wnaf[i]-1));
        }
        else if(x_wnaf[i] < 0) {
          pt.addMutable(P.get(-x_wnaf[i]));
        }
      }
      
      pt.toAffine(this); pt.z.recycle();
    }
    else {
      for(int i = x_wnaf.length - 1; i >= 0; i--)
      {
        twiceMutable();
      
        if(x_wnaf[i] > 0) {
          addMutable(P.get(x_wnaf[i]-1));
        }
        else if(x_wnaf[i] < 0) {
          addMutable(P.get(-x_wnaf[i]));
        }
      }
    }
    
    twoP.recycle();
    for(int i = 0; i < P.size(); i++)
      P.get(i).recycle();
    return this;
  }

  @Override
  public AffinePoint<E, F> negate()
  {
    return invert();
  }

  @Override
  public AffinePoint<E, F> invert()
  {
    if (infinite) {
      return clone();
    }

    return new AffinePoint<E, F>(field, x.clone(), y.negate());
  }

  @Override
  public AffinePoint<E, F> square()
  {
    return twice();
  }

  @Override
  public AffinePoint<E, F> twice()
  {
    return clone().twiceMutable();
  }
  
  /**
   * Copies a point
   * 
   * @return A new instance, representing a copy of this point
   */
  public AffinePoint<E, F> clone()
  {
    return new AffinePoint<E, F>(field, x.clone(), y.clone(), infinite);
  }
  
  @Override
  public boolean equals(Object obj)
  {
    if(obj == this)
      return true;
    
    if(!(obj instanceof AffinePoint<?, ?>))
      return false;
    
    AffinePoint<?, ?> other = (AffinePoint<?, ?>) obj;
    return other.x.equals(x) && other.y.equals(y)
           && other.infinite == infinite;
  }

  @Override
  public AffinePoint<E, F> pow(BigInteger exponent)
  {
    return mul(exponent);
  }

  @Override
  public boolean isZero()
  {
    return infinite;
  }

  @Override
  public boolean isOne()
  {
    return isZero();
  }
  
  /**
   * Return whether this point is infinite.
   * Note that invalid points are also denoted as infinite.
   * 
   * @return true if infinite, false otherwise
   */
  public boolean isInfinite()
  {
    return isZero();
  }

  /**
   * Return whether this point is valid (that is, y^2 = x^3 + ax + b)
   * 
   * @return true if valid, false otherwise
   */
  public boolean isValid()
  {
    E yy = y.square();
    E xx = x.square();
    boolean valid = yy.equals(xx.addMutable(field.getA())
                              .mulMutable(x).addMutable(field.getB()));
    yy.recycle(); xx.recycle();
    return valid;
  }

  @Override
  public boolean isAffine()
  {
    return true;
  }

  @Override
  public AffinePoint<E, F> sqrt()
  {
    throw new UnsupportedOperationException("Not implemented.");
  }

  /**
   * This method is intentionally hidden down here. But anyways, since 
   * you found it: This one is copied from the jPBC, I did not find any
   * solid source for these values though.
   * 
   * See, for example
   * "On the Efficiency Analysis of wNAF and wMOF" 
   * <a href="https://www-old.cdc.informatik.tu-darmstadt.de/reports/
   *                  reports/Fan.diplom.wNAF_wMOF_final.pdf">Fang</a>, p. 27
   * 
   * @param n The BigInteger to get the window size for
   * 
   * @return The 'optimal' window size for the wNAF
   */
  protected byte optimalPowWindowSize(BigInteger n) 
  {
    int expBits = n.bitLength();

    if (expBits > 9065)
      return 8;
    if (expBits > 3529)
      return 7;
    if (expBits > 1324)
      return 6;
    if (expBits > 474)
      return 5;
    if (expBits > 157)
      return 4;
    if (expBits > 47)
      return 3;
    return 2;
  }

  @Override
  public Point<E, F> mulMutable(Point<E, F> element)
  {
    return addMutable(element);
  }

  @Override
  public Point<E, F> addMutable(Point<E, F> element)
  {
    // see, e.g., https://tools.ietf.org/html/rfc6090#appendix-F
    // for a useful guide to affine point addition and doubling
        
    if(infinite) {
      x = element.x.clone();
      y = element.y.clone();
      infinite = element.infinite;
      return this;
    }

    if(element.infinite)
      return this;
    
    if(x.equals(element.x))
    {
      if(y.equals(element.y)) // this == element
        return twiceMutable();

      infinite = true;
      return this;
    }

    E xxinv = element.x.sub(x).invertMutable();
    E lambda = element.y.sub(y).mulMutable(xxinv);
    E tmp = x;
    x = lambda.square().subMutable(x).subMutable(element.x);
    E tmp2 = y;
    y = lambda.mulMutable(tmp.subMutable(x)).subMutable(tmp2);
    tmp.recycle();
    tmp2.recycle();
    xxinv.recycle();
    infinite = false;
    return this;
  }

  @Override
  public Point<E, F> subMutable(Point<E, F> element)
  {
    Point<E, F> minuse = element.negate();
    addMutable(minuse);
    minuse.recycle();
    return this;
    //return negateMutable().addMutable(element);
  }

  @Override
  public Point<E, F> sub(Point<E, F> element)
  {
//    Point<E,F> eminus = element.negate();
//    Point<E, F> out = add(eminus);
//    eminus.recycle();
//    return out;
    return clone().subMutable(element);
  }

  @Override
  public AffinePoint<E, F> invertMutable()
  {
    if (infinite)
      return this;

    y.negateMutable();
    return this;
  }

  @Override
  public AffinePoint<E, F> twiceMutable()
  {
    // = doubling
    // see, e.g., https://tools.ietf.org/html/rfc6090#appendix-F
    // for a useful guide to affine point addition and doubling
    
    if(infinite || y.isZero())
      return this;
    
    E yinv = y.invert();
    E lambda = x.square().addMutable(field.aThird).mulMutable(field.threeHalves)
                .mulMutable(yinv);
    E tmp = x, tmp2 = y, tmptwice = tmp.twice();
    x = lambda.square().subMutable(tmptwice);
    y = lambda.mulMutable(tmp.subMutable(x)).subMutable(tmp2);
    tmp.recycle();
    tmp2.recycle();
    tmptwice.recycle();
    yinv.recycle();
    infinite = false;
    return this;
  }

  @Override
  public AffinePoint<E, F> negateMutable()
  {
    return invertMutable();
  }

  @Override
  public AffinePoint<E, F> squareMutable()
  {
    return twiceMutable();
  }

  @Override
  public AffinePoint<E, F> sqrtMutable()
  {
    throw new UnsupportedOperationException("Not implemented.");
  }

  @Override
  public Point<E, F> divByTwoMutable()
  {
    throw new UnsupportedOperationException("not implemented.");
  }

  @Override
  public Point<E, F> toProjective()
  {
    return new ProjectivePoint<E, F>(field, x.clone(), y.clone(), 
                                     x.getField().getOneElement());
  }

  @Override
  public Point<E, F> toAffine()
  {
    return this;
  }
  
  @Override
  public Point<E, F> toAffine(Point<E, F> affine)
  {
    affine.x = x;
    affine.y = y;
    affine.infinite = infinite;
    return affine;
  }
  
  @Override
  public void recycle()
  {
    x.recycle();
    y.recycle();
  }
  
  /**
   * Creates a point from a given x coordinate
   * 
   * @param x The x coordinate
   */
  public void setFromX(E x)
  {
    if(this.x != null) this.x.recycle();
    if(this.x != null) this.y.recycle();
    this.x = x;
    this.y = x.square().addMutable(field.getA())
                       .mulMutable(x).addMutable(field.getB()).sqrtMutable();
    infinite = false;
    if(this.y == null) // null if sqrt() wasn't possible
    {
      infinite = true;
      this.y = field.getField().getZeroElement();
    }
  }
}
