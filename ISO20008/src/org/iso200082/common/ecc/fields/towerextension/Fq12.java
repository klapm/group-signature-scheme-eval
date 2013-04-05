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
import java.util.Arrays;
import java.util.Random;

import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.elements.Fq12Element;
import org.iso200082.common.ecc.elements.Fq6Element;
import org.iso200082.common.ecc.elements.doubleprecision.Fq12DoubleElement;
import org.iso200082.common.ecc.elements.doubleprecision.Fq6DoubleElement;
import org.iso200082.common.util.Creator;
import org.iso200082.common.util.RecycleBin;

/**
 * Represents the tower extension field F(q^12).
 * 
 * See {@link Field} for interface-level descriptions and
 * {@link TowerExtensionField} for other overridden method descriptions.
 * 
 * @see Field
 * @see TowerExtensionField
 * @see Fq12Element
 * 
 * @param <P> The primitive Type to use
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Fq12<P>
extends TowerExtensionField<Fq12Element<P>, Fq6Element<P>, Fq12<P>, Fq6<P>>
{
  
  /** recycler for single-precision Fq12 elements */
  private RecycleBin<Fq12Element<P>, Fq6Element<P>> single_recycler;

  /** recycler for double-precision Fq12 elements */
  private RecycleBin<Fq12DoubleElement<P>, Fq6DoubleElement<P>> double_recycler;

  /**
   * Ctor, sets the irreducible coefficient that was used to create the field
   * 
   * (e.g. if F(q^12) = F(q^6)[w](w^2 - gamma), then gamma is the irreducible
   * polynomial coefficient)
   * 
   * @param random A {@link Random} instance
   * @param irreduciblePolyCoefficient The gamma coefficient
   */
  @SuppressWarnings({ "rawtypes", "unchecked" })
  public Fq12(Random random, Fq6Element<P> irreduciblePolyCoefficient)
  {
    super(random, irreduciblePolyCoefficient);
    single_recycler = new RecycleBin<Fq12Element<P>, Fq6Element<P>>(
                      new Fq12Element[10], new SingleCreator());
    double_recycler = new RecycleBin<Fq12DoubleElement<P>, Fq6DoubleElement<P>>(
                      new Fq12DoubleElement[5], new DoubleCreator());
  }

  @Override
  public Fq12Element<P> getRandomElement()
  {
    return getElement(getBaseField().getRandomElement(),
                      getBaseField().getRandomElement());
  }

  @Override
  public Fq12Element<P> getOneElement()
  {
    return getElement(getBaseField().getOneElement(),
                      getBaseField().getZeroElement());
  }

  @Override
  public Fq12Element<P> getZeroElement()
  {
    return getElement(getBaseField().getZeroElement(),
                      getBaseField().getZeroElement());
  }

  @Override
  public BigInteger getOrder()
  {
    return getBaseField().getOrder().pow(2);
  }

  @Override
  public int getNumberOfCoefficients()
  {
    return 2;
  }

  @Override
  public int getTotalNumberOfCoefficients()
  {
    return getBaseField().getTotalNumberOfCoefficients() * 
           getNumberOfCoefficients();
  }

  @Override
  public Fq12Element<P> getElementFromByteArray(byte[] data)
  {
    // assumes that all components are of same length
    // (being math.ceil(q.bitlen/8))
    
    if(data.length % getTotalNumberOfCoefficients() != 0)
      throw new IllegalArgumentException("Malformed byte array");
    
    int len = data.length, half = len / getNumberOfCoefficients();
    return getElement(getBaseField().getElementFromByteArray(
                        Arrays.copyOfRange(data, 0, half)),
                      getBaseField().getElementFromByteArray(
                        Arrays.copyOfRange(data, half, len))
                      );
  }

  @Override
  public Fq12Element<P> getElementFromComponents(BigInteger... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    int len = components.length, half = len / getNumberOfCoefficients();
    
    return getElement(getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, 0, half)),
                      getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, half, len))
                      );
  }

  @Override
  public Fq12Element<P> getElementFromComponents(long... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    int len = components.length, half = len / getNumberOfCoefficients();
    
    return getElement(getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, 0, half)),
                      getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, half, len))
                      );
  }

  @Override
  public Fq12Element<P> getElementFromComponents(String... components)
  {
    return getElementFromComponents(10, components);
  }

  @Override
  public Fq12Element<P> getElementFromComponents(int radix, String... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    int len = components.length, half = len / getNumberOfCoefficients();
    
    return getElement(getBaseField().getElementFromComponents(radix,
                        Arrays.copyOfRange(components, 0, half)),
                      getBaseField().getElementFromComponents(radix,
                        Arrays.copyOfRange(components, half, len))
                      );
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq12Element<P> getElementFromComponents(Fq6Element<P>... elements)
  {
    if(elements.length != getNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
  
    return getElement(elements[0], elements[1]);
  }

  /**
   * Returns a new Fq12 element from the given Fq6 components a, b.
   * 
   * @param a Component a
   * @param b Component b
   * 
   * @return the newly created Fq12 element
   */
  @SuppressWarnings("unchecked")
  public Fq12Element<P> getElement(Fq6Element<P> a, Fq6Element<P> b)
  {
    return single_recycler.get(a, b);
  }

  /**
   * Returns a new Fq12 double-precision element from the given Fq6 components
   * a, b.
   * 
   * @param a Component a
   * @param b Component b
   * 
   * @return the newly created Fq12 double-precision element
   */
  @SuppressWarnings("unchecked")
  public Fq12DoubleElement<P> 
  getDoubleElement(Fq6DoubleElement<P> a, Fq6DoubleElement<P> b)
  {
    return double_recycler.get(a, b);
  }
  
  /**
   * Returns a given element to the pool of available ones
   * 
   * @param element The element to recycle
   */
  public void recycle(Fq12DoubleElement<P> element)
  {
    double_recycler.put(element);
  }

  @Override
  public void recycle(Fq12Element<P> element)
  {
    single_recycler.put(element);
  }

  private class SingleCreator
  implements Creator<Fq12Element<P>, Fq6Element<P>>
  {

    @Override
    @SuppressWarnings("unchecked")
    public Fq12Element<P> create(Fq6Element<P>... values)
    {
      return new Fq12Element<P>(Fq12.this, values[0], values[1]);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Fq12Element<P>
    fromObject(Fq12Element<P> obj, Fq6Element<P>... values)
    {
      obj.a = values[0];
      obj.b = values[1];
      return obj;
    }
    
  }

  private class DoubleCreator
  implements Creator<Fq12DoubleElement<P>, Fq6DoubleElement<P>>
  {

    @Override
    @SuppressWarnings("unchecked")
    public Fq12DoubleElement<P> create(Fq6DoubleElement<P>... values)
    {
      return new Fq12DoubleElement<P>(Fq12.this, values[0], values[1]);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Fq12DoubleElement<P>
    fromObject(Fq12DoubleElement<P> obj, Fq6DoubleElement<P>... values)
    {
      obj.a = values[0];
      obj.b = values[1];
      return obj;
    }
    
  }

}
