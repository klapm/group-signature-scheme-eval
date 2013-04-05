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

package org.iso200082.common.ecc.fields;


import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import org.iso200082.common.Debug;
import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.api.FieldElement;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.AffinePoint;


/**
 * Represents a curve field, defined by the reduced weierstrass equation
 * y^2 = x^3 + ax +b. 'a' is not used (yet), since only Barreto-Naehrig
 * curves are used as of now and a is zero there.
 * See "Pairing-Friendly Elliptic Curves of Prime Order" (Barreto, Naehrig).
 *
 * @param <E> The field's internal Elements (the type of the Point's
 *            coordinates) 
 * @param <F> The Point's coordinate-field
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class CurveField
<
  E extends FieldElement<E, F>,
  F extends Field<E, F>
>
implements Field<Point<E, F>, CurveField<E, F>>
{ 
  
  /** A {@link Random} instance */
  protected Random rnd;
  
  /** 'a' as in y^2 = x^3 + ax + b */
  protected E a;

  /** 'b' as in y^2 = x^3 + ax + b */
  protected E b;
  
  /** The curve's order (number of points * cofactor) */
  protected BigInteger order;
  
  /** The cofactor */
  protected BigInteger cofactor;
  
  /** The embedded field */
  protected Field<E, F> field;

  /** 3/2 mod q, used in affine point mult. */
  public E threeHalves;
  
  /** 1/3 mod q, used in affine point mult. */
  public E aThird; 

  /** whether or not to use a coordinate mix in point multiplication */
  protected boolean mixed_mode;
  
  /**
   * Ctor, initializes the curve equation with the given values
   * 
   * @param rnd A {@link Random} instance
   * @param field The embedded field
   * @param a 'a' as in y^2 = x^3 + ax + b
   * @param b 'b' as in y^2 = x^3 + ax + b
   * @param order The curve's order
   * @param cofactor The cofactor 
   * @param mixed_mode Whether or not to use a coordinate mix in
   *                   point multiplication
   */
  public CurveField(Random rnd, Field<E, F> field, E a, E b,
                    BigInteger order, BigInteger cofactor, boolean mixed_mode)
  {
    this.rnd        = rnd;
    this.field      = field;
    this.a          = a;
    this.b          = b;
    this.order      = order;
    this.cofactor   = cofactor;
    this.mixed_mode = mixed_mode;

    threeHalves  = field.getOneElement().mulMutable(BigInteger.valueOf(3))
                        .divByTwoMutable();
    aThird       = a.mul(field.getOneElement().mulMutable(BigInteger.valueOf(3))
                    .invertMutable());
  }
  
  /**
   * Returns a random generator point of this field
   * 
   * @return A random genrator point
   */
  public Point<E, F> getRandomGenerator()
  {
    return getRandomElement().mulMutable(cofactor);
  }
  
  @Override
  public BigInteger getOrder()
  {
    return order;
  }

  /**
   * Getter for the embedded field
   * @return The field
   */
  public Field<E, F> getField()
  {
    return field;
  }
  
  /**
   * getter for the coefficient a
   * @return a
   */
  public E getA()
  {
    return a;
  }

  /**
   * getter for the coefficient b
   * @return b
   */
  public E getB()
  {
    return b;
  }

  /**
   * getter for the cofactor
   * @return The cofactor
   */
  public BigInteger getCofactor()
  {
    return cofactor;
  }

  @Override
  public String toString()
  {
    return "CurveField:\n"
           + "[y^2 = x^3 + " + a + "x^2 + " + b + "\n"
           + " order = " + order + ", cofactor = " + cofactor + "]";
  }

  @Override
  public Point<E, F> getRandomElement()
  {
    AffinePoint<E, F> out = 
      new AffinePoint<E, F>(this, field.getRandomElement());
    
    while(out.infinite) // happens if the random is not a QR
      out.setFromX(field.getRandomElement());
    
    return out;
  }

  @Override
  public Point<E, F> getOneElement()
  {
    Point<E, F> pt =
      new AffinePoint<E, F>(this, field.getOneElement(),
                            field.getZeroElement());
    return pt;
  }

  @Override
  public Point<E, F> getZeroElement()
  {
    Point<E, F> pt =
      new AffinePoint<E, F>(this);
    return pt;
  }

  /**
   * Creates a valid point from a given x coordinate (computes y).
   * 
   * @param x The x coordinate
   * 
   * @return A new point with given x and computed y
   */
  public Point<E, F> getElementFromX(E x)
  {
    // might return infinite points if x is invalid.
    Point<E, F> out = new AffinePoint<E, F>(this, x);
    return out;
  }
  
  @Override
  public Point<E, F> getElementFromByteArray(byte[] data)
  {
    // assumes that all components are of same length
    // (being math.ceil(q.bitlen/8))
    
    // always uses projective coords. if affine, z is the one-element
    if(data.length % getTotalNumberOfCoefficients() == 0)
    {
      int len = data.length, half = len / 2;
      return new AffinePoint<E, F>(
                 this,
                 field.getElementFromByteArray(
                   Arrays.copyOfRange(data, 0, half)),
                 field.getElementFromByteArray(
                   Arrays.copyOfRange(data, half, len))
                 );
    }
    
    throw new IllegalArgumentException("Invalid number of coefficients");
  }

  @Override
  public Point<E, F> getElementFromComponents(BigInteger... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("Invalid number of coefficients");
    
    int len = components.length, half = len / 2;
    return new AffinePoint<E, F>(
               this,
               field.getElementFromComponents(
                 Arrays.copyOfRange(components, 0, half)),
               field.getElementFromComponents(
                 Arrays.copyOfRange(components, half, len))
               );
  }

  @Override
  public Point<E, F> getElementFromComponents(long... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("Invalid number of coefficients");
    
    int len = components.length, half = len / 2;
    return new AffinePoint<E, F>(this,
               field.getElementFromComponents(
                 Arrays.copyOfRange(components, 0, half)),
               field.getElementFromComponents(
                 Arrays.copyOfRange(components, half, len))
               );
  }

  @Override
  public Point<E, F> getElementFromComponents(String... components)
  {
    return getElementFromComponents(10, components);
  }

  @Override
  public Point<E, F> getElementFromComponents(int radix, String... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("Invalid number of coefficients");
    
    int len = components.length, half = len / 2;
    return new AffinePoint<E, F>(this,
               field.getElementFromComponents(
                 Arrays.copyOfRange(components, 0, half)),
               field.getElementFromComponents(
                 Arrays.copyOfRange(components, half, len))
               );
  }

  @Override
  public int getNumberOfCoefficients()
  {
    return 2;
  }

  @Override
  public int getTotalNumberOfCoefficients()
  {
    return field.getTotalNumberOfCoefficients() * getNumberOfCoefficients();
  }
  
  /**
   * Returns whether to use plain affine point multiplication or mixed-mode.
   * 
   * @return true when a mix of affine and projective coordinates shall be 
   *         used, false otherwise
   */
  public boolean useMixedModeMultiplication()
  {
    return mixed_mode;
  }

}
