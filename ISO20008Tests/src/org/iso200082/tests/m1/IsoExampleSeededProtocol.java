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

package org.iso200082.tests.m1;


import java.math.BigInteger;

import org.iso200082.mechanisms.m1.ds.M1PrecomputationResult;
import org.iso200082.mechanisms.m1.ds.M1Signature;
import org.iso200082.mechanisms.m1.ds.M1SignatureKey;
import org.iso200082.mechanisms.m1.ds.group.M1Parameters;
import org.iso200082.mechanisms.m1.ds.group.M1PublicKey;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;


/**
 * Just a derived class from protocol to provide another wrapper
 * for the internal sign command which uses pre-seeded randoms as given in
 * the parameters.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see M1Protocol
 */
public class IsoExampleSeededProtocol extends M1Protocol
{  
  
  public static M1Signature sign(
      BigInteger bsn, String message, M1PublicKey gpub, M1SignatureKey key, 
      M1Parameters params, BigInteger w1, BigInteger w2, BigInteger w3,
      BigInteger r1, BigInteger r2, BigInteger r3, BigInteger r4, 
      BigInteger r5, BigInteger r9, BigInteger r10)
  {
    M1PrecomputationResult precomp =
        precomputeInitialSignatureInternal(gpub, key, params, w1, w2, w3,
                                    r1, r2, r3, r4, r5, r9, r10);
    return signMessage(bsn, message, gpub, key, params, precomp);
  }

}
