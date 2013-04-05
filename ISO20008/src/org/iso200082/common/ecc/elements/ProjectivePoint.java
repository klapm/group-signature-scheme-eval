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

/**
 * Elliptic curve point, projective (jacobian) coordinates, immutable.
 * (x,y,z) projective = (x/z^2, y/z^3) affine 
 * 
 * Supports addition, doubling and scalar multiplication.
 * 
 * @see FieldElement
 * @see CurveField
 * @see AffinePoint
 * @see Point
 * 
 * @param <E> The contained element's types (x,y)
 * @param <F> The element's field
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class ProjectivePoint
<
  E extends FieldElement<E, F>,
  F extends Field<E, F>
>
extends Point<E,F>
{
  /** '3' as {@link BigInteger} */
  private static final BigInteger THREE = BigInteger.valueOf(3);

  /** '8' as {@link BigInteger} */
  private static final BigInteger EIGHT = BigInteger.valueOf(8);
  
  /**
   * Ctor, initializes both x and y to zero (leading to point being infinite).
   * 
   * @param field The corresponding field
   */
  public ProjectivePoint(CurveField<E, F> field)
  {
    this.field = field;
    x = field.getField().getZeroElement();
    y = field.getField().getZeroElement();
    z = field.getField().getOneElement();
    infinite = true;
  }

  /**
   * Ctor, initializes x, y and z to the given x, y and z. The values are 
   * verified and the point is infinite if these values weren't ok
   * (for this curve).
   * 
   * @param field The corresponding field
   * @param x Given x coordinate value
   * @param y Given y coordinate value
   * @param z Given z coordinate value
   */
  public ProjectivePoint(CurveField<E, F> field, E x, E y, E z)
  {
    this.field = field;
    this.x = x;
    this.y = y;
    this.z = z;
    infinite = !isValid();
  }

  /**
   * Ctor that does not copy. Used internally at {@link #clone()}.
   * 
   * @param field The corresponding field
   * @param x Given x coordinate value
   * @param y Given y coordinate value
   * @param z Given z coordinate value
   * @param inf Infinity flag
   */
  protected ProjectivePoint(CurveField<E, F> field, E x, E y, E z, boolean inf)
  {
    this.field = field;
    this.x = x;
    this.y = y;
    this.z = z;
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
  public ProjectivePoint(CurveField<E, F> field, E x)
  {
    this.field = field;
    
    this.x = x.clone();
    this.y = x.square().addMutable(field.getA())
                       .mulMutable(x).addMutable(field.getB()).sqrtMutable();
    this.z = x.getField().getOneElement();
    infinite = false;
    if(this.y == null) // null if sqrt() wasn't possible
    {
      infinite = true;
      this.y = field.getField().getZeroElement();
    } 
  }
  
  @Override
  public Point<E, F> add(Point<E, F> element)
  {
    return clone().addMutable(element);
  }

  @Override
  public Point<E, F> addMutable(Point<E, F> element)
  {
    /* 
     * Hankerson-Menezes-Vanstone addition as in 
     * Hankerson, Menezes, Vanstone "Guide to Elliptic Cryptography" 
     * 2nd ed., Springer, 2004
     * 
     * or
     * http://www.hyperelliptic.org/EFD/g1p/
     * auto-shortw-jacobian-0.html#addition-madd-2004-hmv
     */
    
    if(!element.isAffine())
      throw new 
      UnsupportedOperationException("only mixed coordinates implemented");
    
    if(infinite)
    {
      x = element.x.clone();
      y = element.y.clone();
      z = x.getField().getOneElement();
      infinite = element.infinite;
      return this;
    }
    
    if(element.infinite)
      return this;
    
    E T1 = z.square();
    E T2 = T1.mul(z);
    E T3 = T1.mulMutable(element.x);
    T1 = T2.mulMutable(element.y);
    T3 = T3.subMutable(x);
    T1 = T1.subMutable(y);
    
    if(T3.isZero()) {
      T1.recycle();
      T3.recycle();
      if(T1.isZero()){
        x = element.x.clone();
        y = element.y.clone();
        z = x.getField().getOneElement();
        infinite = false;
        return twiceMutable();
      }
      else
      {
        infinite = true;
        return this;
      }
    }
    
    z = z.mulMutable(T3);
    T2 = T3.square();
    E T4 = T2.mul(T3);
    T3.recycle();
    T3 = T2.mulMutable(x);
    T2 = T3.twice();
    x.recycle();
    x = T1.square().subMutable(T2).subMutable(T4);
    T3 = T3.subMutable(x);
    T2.recycle();
    T2 = T3.mulMutable(T1);
    T1.recycle();
    T1 = T4.mulMutable(y);
    y.recycle();
    y = T2.subMutable(T1);
    
    T1.recycle();
    return this;
  }

  @Override
  public Point<E, F> sub(Point<E, F> element)
  {
    return clone().subMutable(element);
  }

  @Override
  public Point<E, F> subMutable(Point<E, F> element)
  {
    Point<E, F> eminus = element.negate();
    Point<E, F> out = addMutable(eminus);
    eminus.recycle();
    return out;
  }

  @Override
  public Point<E, F> mul(Point<E, F> element)
  {
    return add(element);
  }

  @Override
  public Point<E, F> mulMutable(Point<E, F> element)
  {
    return addMutable(element);
  }

  @Override
  public Point<E, F> mul(BigInteger bi)
  {
    return clone().mulMutable(bi);
  }

  @Override
  public Point<E, F> mulMutable(BigInteger bi)
  {

    /* 
     * Windowed NAF (wNAF) method for point multiplication as in 
     * Hankerson, Menezes, Vanstone "Guide to Elliptic Cryptography" 
     * 2nd ed., Springer, 2004
     */
    
    if(infinite || bi.equals(BigInteger.ONE))
      return this;

    if(bi.equals(BigInteger.ZERO)) {
      infinite = true;
      return this;
    }
            
    byte w = IntegerUtil.optimalPowWindowSize(bi);
    byte[] x_wnaf = IntegerUtil.wnaf(bi, w);
    
    ArrayList<Point<E, F>> P = new ArrayList<Point<E, F>>();
    P.add(clone().toAffine());
    Point<E, F> twoP = P.get(0).twice();
    for(int j = 0, i = 3; i < (1 << (w - 1)); i += 2, j++)
      P.add(P.get(j).add(twoP));

    infinite = true;    
    for(int i = x_wnaf.length - 1; i >= 0; i--)
    {
      twiceMutable();
    
      if(x_wnaf[i] > 0) {
        addMutable(P.get(x_wnaf[i]/2));
      }
      else if(x_wnaf[i] < 0) {
        subMutable(P.get(-x_wnaf[i]/2));
      }
    }
    
    return this;
  }

  @Override
  public Point<E, F> negate()
  {
    return clone().invertMutable();
  }

  @Override
  public Point<E, F> negateMutable()
  {
    return invertMutable();
  }

  @Override
  public Point<E, F> invert()
  {
    return clone().negateMutable();
  }

  @Override
  public Point<E, F> invertMutable()
  {
    if (infinite)
      return this;

    y = y.negateMutable();
    return this;
  }

  @Override
  public Point<E, F> square()
  {
    return clone().squareMutable();
  }

  @Override
  public Point<E, F> squareMutable()
  {
    return twiceMutable();
  }

  @Override
  public Point<E, F> twice()
  {
    return clone().twiceMutable();
  }

  @Override
  public Point<E, F> twiceMutable()
  {
    /*
     *  Point double as by Lange, 2009. See
     *  http://www.hyperelliptic.org/EFD/g1p/
     *  auto-shortw-jacobian-0.html#doubling-dbl-2009-l
     */
    
    if(infinite) {
      return this;
    }
    
    E XX = x.square();
    E YY = y.square();
    E YYYY = YY.square();
    E ZZ = z.square();
    E S = x.add(YY).squareMutable().subMutable(XX).subMutable(YYYY)
           .twiceMutable();
    E ZZZZ = ZZ.square();
    E aZZZZ = field.getA().mul(ZZZZ);
    E M = XX.mulMutable(THREE).addMutable(aZZZZ);
    x.recycle();
    E SS = S.twice();
    x = M.square().subMutable(SS);
    E tmp = y;
    y = M.mulMutable(S.subMutable(x)).subMutable(YYYY.mulMutable(EIGHT));
    z.recycle(); // does not deleted it (yet)
    z = tmp.addMutable(z).squareMutable().subMutable(YY).subMutable(ZZ);
    YY.recycle();
    YYYY.recycle();
    ZZ.recycle();
    ZZZZ.recycle();
    aZZZZ.recycle();
    S.recycle();
    SS.recycle();
    return this;
  }

  @Override
  public Point<E, F> pow(BigInteger exponent)
  {
    return mul(exponent);
  }

  @Override
  public Point<E, F> sqrt()
  {
    throw new UnsupportedOperationException("not implemented");
  }

  @Override
  public Point<E, F> sqrtMutable()
  {
    throw new UnsupportedOperationException("not implemented");
  }

  @Override
  public Point<E, F> divByTwoMutable()
  {
    throw new UnsupportedOperationException("not implemented");
  }

  @Override
  public byte[] toByteArray()
  {
    // not implemented (was not needed)
    return null;
  }
  
  @Override
  public String toString()
  {
    return toString(10);
  }

  @Override
  public String toString(int radix)
  {
    return "JacobPt([" + x.toString(radix) + ", " 
                       + y.toString(radix) + ", " 
                       + z.toString(radix) + "], "
                       + "infinite: " 
                       + (infinite ? "true" : "false")
                       + ")";
  }

  @Override
  public boolean isZero()
  {
    return infinite;
  }

  @Override
  public boolean isOne()
  {
    return infinite;
  }

  @Override
  public Point<E, F> clone()
  {
    return 
    new ProjectivePoint<E, F>(field, x.clone(), y.clone(), z.clone(), infinite);
  }

  @Override
  public Point<E, F> toProjective()
  {
    return this;
  }

  @Override
  public Point<E, F> toAffine()
  {
    E z_inv  = z.invert();
    E z_inv2 = z_inv.square();
    
    E outx = x.mulMutable(z_inv2);
    z_inv2 = z_inv2.mulMutable(z_inv);
    E outy = y.mulMutable(z_inv2);
    z_inv.recycle();
    z_inv2.recycle();
    return new AffinePoint<E, F>(field, outx, outy, infinite);
  }

  @Override
  public Point<E, F> toAffine(Point<E, F> affine)
  {
    E z_inv  = z.invert();
    E z_inv2 = z_inv.square();
    
    affine.x = x.mulMutable(z_inv2);
    z_inv2 = z_inv2.mulMutable(z_inv);
    affine.y = y.mulMutable(z_inv2);
    affine.infinite = infinite;
    z_inv.recycle();
    z_inv2.recycle();
    return affine;
  }

  @Override
  public boolean isValid()
  {
    E left, right, temp;
    left = x.square();
    right = left.mulMutable(x);
    left = z.square();
    temp = left.square();
    left = left.mulMutable(temp);
    left = left.mulMutable(field.getB());
    right = left.addMutable(right);
    temp = temp.mulMutable(x);
    temp = temp.mulMutable(field.getA());
    right = right.addMutable(temp);
    left = y.square();
    
    left.recycle();
    right.recycle();
    temp.recycle();
    return left.equals(right);
  }

  @Override
  public boolean isAffine()
  {
    return false;
  }

  @Override
  public Point<E, F> mul(FqElement<?> element)
  {
    return mul(element.toBigInteger());
  }

  @Override
  public void recycle()
  {
    x.recycle();
    y.recycle();
    z.recycle();
  }
}
