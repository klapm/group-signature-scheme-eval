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
import java.util.Random;

import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.api.FieldElement;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.fields.towerextension.Fq2;


/**
 * Well, let's just say that a 'typedef' instruction would've avoided this
 * class entirely. It's sole purposes is to avoid writing
 * CurveField<Fq2Element, Fq2> all the time. 
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class G2
<
  P
>
extends CurveField<Fq2Element<P>, Fq2<P>>
{
  /**
   * Ctor, initializes the curve field. See
   * {@link CurveField#CurveField(Random, Field, FieldElement, FieldElement, 
   * BigInteger, BigInteger, boolean)}. Strips the 'a' coefficient since it's
   * zero for our purposes.
   * 
   * @param rnd A {@link Random} instance
   * @param field The embedded field
   * @param b 'b' as in y^2 = x^3 + ax + b
   * @param order The curve's order
   * @param cofactor The cofactor
   * @param mixed_mode Whether the point multiplication should use a coordinate
   *                   mix or not
   */
  public G2(Random rnd, Field<Fq2Element<P>, Fq2<P>> field, Fq2Element<P> b,
            BigInteger order, BigInteger cofactor, boolean mixed_mode)
  {
    super(rnd, field, field.getZeroElement(), b, order, cofactor, mixed_mode);
  }
}
