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

package org.iso200082.common.ecc.api;

import org.iso200082.common.ecc.elements.Fq12Element;
import org.iso200082.common.ecc.fields.towerextension.Fq12;

/**
 * Represents a pairing result (as of now it's just a {@link Fq12Element}).
 * 
 * Note that it still exposes {@link Fq12Element}s when performing any
 * operations on {@link PairingResult}s.
 * 
 * @param <P> The primitive Type to use 
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface PairingResult
<
  P
>
extends FieldElement<Fq12Element<P>, Fq12<P>>
{
  // intentionally empty (for now).
}
